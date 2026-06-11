// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager Applet -- allow user control over networking
 *
 * Lubomir Rintel <lkundrak@v3.sk>
 *
 * Copyright (C) 2016 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include "nma-cert-chooser-button.h"
#include "utils.h"

#if WITH_GCR
#include "nma-pkcs11-cert-chooser-dialog.h"
#include <gck/gck.h>
#if !GCK_CHECK_VERSION(3,90,0)
#define gck_uri_data_parse gck_uri_parse
#define gck_uri_data_build gck_uri_build
#define gck_slot_open_session_async(self, options, interaction, cancellable, callback, user_data) \
	gck_slot_open_session_async(self, options, cancellable, callback, user_data)
#endif
#endif

/**
 * SECTION:nma-cert-chooser-button
 * @title: NMACertChooserButton
 * @short_description: The PKCS\#11 or file certificate chooser button
 *
 * #NMACertChooserButton is a button that provides a dropdown of
 * PKCS\#11 slots present in the system and allows choosing a certificate
 * from either of them or a file.
 */

enum {
	CHANGED,
	LAST_SIGNAL,
};

enum {
	COLUMN_LABEL,
	COLUMN_SLOT,
	N_COLUMNS
};

typedef struct {
	gchar *title;
	gchar *uri;
	gchar *pin;
	gboolean remember_pin;
	gboolean has_matching_key;
	NMACertChooserButtonFlags flags;
	gboolean modules_ready;        /* modules_initialized отработал */
	gboolean autoselect_requested; /* автовыбор ждёт завершения перечисления */

	GtkWidget *button;
	GtkWidget *button_label;
} NMACertChooserButtonPrivate;

G_DEFINE_TYPE (NMACertChooserButton, nma_cert_chooser_button, GTK_TYPE_BOX);

enum {
	PROP_0,
	PROP_FLAGS,
	LAST_PROP
};

#define NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                NMA_TYPE_CERT_CHOOSER_BUTTON, \
                                                NMACertChooserButtonPrivate))

static void
update_title (NMACertChooserButton *button);

#if WITH_GCR
static void autoselect_from_combo_model (NMACertChooserButton *button);

static gboolean
is_this_a_slot_nobody_loves (GckSlot *slot)
{
	GckSlotInfo *slot_info;
	gboolean ret_value = FALSE;

	slot_info = gck_slot_get_info (slot);
	if (!slot_info)
		return TRUE;

	/* The p11-kit CA trusts do use their filesystem paths for description. */
	if (g_str_has_prefix (slot_info->slot_description, "/"))
		ret_value = TRUE;
	else if (NM_IN_STRSET (slot_info->slot_description,
	                       "SSH Keys",
	                       "Secret Store",
	                       "User Key Storage"))
		ret_value = TRUE;

	gck_slot_info_free (slot_info);

	return ret_value;
}

static void
modules_initialized (GObject *object, GAsyncResult *res, gpointer user_data)
{
	NMACertChooserButton *self = NMA_CERT_CHOOSER_BUTTON (user_data);
	NMACertChooserButtonPrivate *priv;
	GList *slots;
	GList *list_iter;
	GError *error = NULL;
	GList *modules;
	GtkTreeIter iter;
	GtkListStore *model;
	GckTokenInfo *info;
	gchar *label;

	if(!NMA_IS_CERT_CHOOSER_BUTTON(self)) {
		return;
	}

	priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (self);

	const char *ignore_opensc = getenv("NMA_IGNORE_OPENSC");
	modules = gck_modules_initialize_registered_finish (res, &error);
	if (error) {
		/* The Front Fell Off. */
		g_warning ("Error getting registered modules: %s", error->message);
		g_clear_error (&error);
	}
	else if(ignore_opensc && strstr(ignore_opensc, "1"))
	{
		for (GList *module = modules; module != NULL; module = module->next) {
			char *manufacturer_id = gck_module_get_info(module->data)->manufacturer_id;
        	if(manufacturer_id && strstr(manufacturer_id, "OpenSC")) {
				modules = g_list_remove_link(modules, module);
				break;
			}
    	}
	}

	model = GTK_LIST_STORE (gtk_combo_box_get_model (GTK_COMBO_BOX (priv->button)));

	/* A separator. */
	gtk_list_store_insert_with_values (model, &iter, 2,
	                                   COLUMN_LABEL, NULL,
	                                   COLUMN_SLOT, NULL, -1);

	slots = gck_modules_get_slots (modules, FALSE);
	for (list_iter = slots; list_iter; list_iter = list_iter->next) {
		GckSlot *slot = GCK_SLOT (list_iter->data);

		if (is_this_a_slot_nobody_loves (slot))
			continue;

		info = gck_slot_get_token_info (slot);
		if (!info) {
			/* This happens when the slot has no token inserted.
			 * Don't add this one to the list. The other widgets
			 * assume gck_slot_get_token_info() don't fail and a slot
			 * for which it does is essentially useless as it can't be
			 * used for crafting an URI. */
			continue;
		}

		if ((info->flags & CKF_TOKEN_INITIALIZED) == 0)
			continue;

		if (info->label && *info->label) {
			label = g_strdup_printf ("%s\342\200\246", info->label);
		} else if (info->model && *info->model) {
			g_warning ("The token doesn't have a valid label");
			label = g_strdup_printf ("%s\342\200\246", info->model);
		} else {
			g_warning ("The token has neither valid label nor model");
			label = g_strdup ("(Unknown)\342\200\246");
		}
		gtk_list_store_insert_with_values (model, &iter, 2,
		                                   COLUMN_LABEL, label,
		                                   COLUMN_SLOT, slot, -1);
		g_free (label);
		gck_token_info_free (info);
	}

	g_list_free_full (slots, g_object_unref);
	g_list_free_full (modules, g_object_unref);

	priv->modules_ready = TRUE;
	if (priv->autoselect_requested) {
		priv->autoselect_requested = FALSE;
		autoselect_from_combo_model (self);
	}
}

static char *
title_from_pkcs11 (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);
	GError *error = NULL;
	char *label = NULL;
	GckUriData *data;

	data = gck_uri_data_parse (priv->uri, GCK_URI_FOR_ANY, &error);
	if (data) {
		if (!gck_attributes_find_string (data->attributes, CKA_LABEL, &label)) {
			if (data->token_info) {
				g_free (label);
				label = g_strdup_printf (  priv->flags & NMA_CERT_CHOOSER_BUTTON_FLAG_KEY
							 ? _("Key in %s")
							 : _("Certificate in %s"),
							 data->token_info->label);
			}
		}
		gck_uri_data_free (data);
	} else {
		g_warning ("Bad URI '%s': %s\n", priv->uri, error->message);
		g_error_free (error);
	}

	return label;
}

static void
select_from_token (NMACertChooserButton *button, GckSlot *slot)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);
	GtkRoot *toplevel;
	GtkWidget *dialog;

	toplevel = gtk_widget_get_root (GTK_WIDGET (button));
	if (toplevel && !GTK_IS_WINDOW (toplevel))
		toplevel = NULL;

	dialog = nma_pkcs11_cert_chooser_dialog_new (slot,
	                                               priv->flags & NMA_CERT_CHOOSER_BUTTON_FLAG_KEY
	                                             ? CKO_PRIVATE_KEY
	                                             : CKO_CERTIFICATE,
	                                             priv->title,
	                                             (GtkWindow *) toplevel,
	                                             GTK_FILE_CHOOSER_ACTION_OPEN | GTK_DIALOG_USE_HEADER_BAR,
	                                             _("Select"), GTK_RESPONSE_ACCEPT,
	                                             _("Cancel"), GTK_RESPONSE_CANCEL,
	                                             NULL);
	if (nma_gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		if (priv->uri)
			g_free (priv->uri);
		priv->uri = nma_pkcs11_cert_chooser_dialog_get_uri (NMA_PKCS11_CERT_CHOOSER_DIALOG (dialog));
		if (priv->pin)
			g_free (priv->pin);
		priv->pin = nma_pkcs11_cert_chooser_dialog_get_pin (NMA_PKCS11_CERT_CHOOSER_DIALOG (dialog));
		priv->remember_pin = nma_pkcs11_cert_chooser_dialog_get_remember_pin (NMA_PKCS11_CERT_CHOOSER_DIALOG (dialog));
		priv->has_matching_key = nma_pkcs11_cert_chooser_dialog_get_has_matching_key (NMA_PKCS11_CERT_CHOOSER_DIALOG (dialog));
		update_title (button);
		g_signal_emit_by_name (button, "changed");
	}
	gtk_window_destroy (GTK_WINDOW (dialog));
}

static void
initialize_gck_modules (NMACertChooserButton *button)
{
	gck_modules_initialize_registered_async (NULL, modules_initialized, button);
}

static int
use_simple_button (NMACertChooserButtonFlags flags)
{
	return flags & NMA_CERT_CHOOSER_BUTTON_FLAG_PEM;
}

/* ---- S7: автоподстановка единственного сертификата с единственного токена ----
 *
 * Перечисляет активные токены и, если в системе ровно один токен и на нём
 * ровно один сертификат, программно выбирает этот сертификат (как если бы
 * пользователь сделал это через диалог) и эмитит "changed", после чего
 * срабатывает уже существующая автоподстановка приватного ключа.
 * Перечисление идёт по публичным объектам без логина (PIN вводится отдельно).
 */

typedef struct {
	NMACertChooserButton *button;   /* g_object_ref на время операции */
	GckSlot *slot;                  /* единственный найденный токен */
	GckSession *session;            /* read-only сессия без логина */
	GHashTable *key_ids;            /* GBytes(CKA_ID) ключей (pub/priv) */
	GPtrArray *certs;               /* GckAttributes* объектов CKO_CERTIFICATE */
	guint pending;                  /* незавершённые gck_object_get_async */
	gboolean enum_done;             /* перечисление вернуло все объекты */
} AutoselectCtx;

static void
autoselect_ctx_free (AutoselectCtx *actx)
{
	if (!actx)
		return;
	if (actx->certs)
		g_ptr_array_unref (actx->certs);
	if (actx->key_ids)
		g_hash_table_unref (actx->key_ids);
	g_clear_object (&actx->session);
	g_clear_object (&actx->slot);
	g_clear_object (&actx->button);
	g_slice_free (AutoselectCtx, actx);
}

static void
autoselect_finish (AutoselectCtx *actx)
{
	GckAttributes *attrs;
	const GckAttribute *id;
	gboolean has_key = FALSE;
	gchar *uri;

	/* По S7 считаем ВСЕ сертификаты на токене. */
	if (actx->certs->len != 1) {
		autoselect_ctx_free (actx);
		return;
	}

	attrs = actx->certs->pdata[0];

	id = gck_attributes_find (attrs, CKA_ID);
	if (id && id->value && id->length) {
		GBytes *id_bytes = g_bytes_new_static (id->value, id->length);

		has_key = g_hash_table_contains (actx->key_ids, id_bytes);
		g_bytes_unref (id_bytes);
	}

	uri = nma_pkcs11_cert_chooser_build_object_uri (actx->slot, attrs, has_key);
	if (uri && NMA_IS_CERT_CHOOSER_BUTTON (actx->button))
		nma_cert_chooser_button_set_uri_autoselected (actx->button, uri, has_key);
	g_free (uri);

	autoselect_ctx_free (actx);
}

static void
autoselect_object_details (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	GckObject *object = GCK_OBJECT (source_object);
	AutoselectCtx *actx = user_data;
	GckAttributes *attrs;
	gulong cka_class;
	const GckAttribute *attr;
	GError *error = NULL;

	attrs = gck_object_get_finish (object, res, &error);
	if (!attrs) {
		g_warning ("Error getting attributes: %s", error->message);
		g_clear_error (&error);
	} else {
		if (gck_attributes_find_ulong (attrs, CKA_CLASS, &cka_class)) {
			switch (cka_class) {
			case CKO_PUBLIC_KEY:
			case CKO_PRIVATE_KEY:
				attr = gck_attributes_find (attrs, CKA_ID);
				if (attr && attr->value && attr->length)
					g_hash_table_add (actx->key_ids,
					                  g_bytes_new (attr->value, attr->length));
				break;
			case CKO_CERTIFICATE:
				g_ptr_array_add (actx->certs, gck_attributes_ref (attrs));
				break;
			default:
				break;
			}
		}
		gck_attributes_unref (attrs);
	}

	if (actx->pending > 0)
		actx->pending--;
	if (actx->enum_done && actx->pending == 0)
		autoselect_finish (actx);
}

static void
autoselect_next_object (GObject *obj, GAsyncResult *res, gpointer user_data)
{
	AutoselectCtx *actx = user_data;
	GckEnumerator *enm = GCK_ENUMERATOR (obj);
	GList *objects;
	GList *iter;
	GError *error = NULL;

	objects = gck_enumerator_next_finish (enm, res, &error);
	g_object_unref (enm);
	if (error) {
		g_warning ("Error getting object: %s", error->message);
		g_clear_error (&error);
		autoselect_ctx_free (actx);
		return;
	}

	for (iter = objects; iter; iter = iter->next) {
		GckObject *object = GCK_OBJECT (iter->data);
		const gulong attr_types[] = { CKA_ID, CKA_LABEL, CKA_CLASS };

		actx->pending++;
		gck_object_get_async (object, attr_types, G_N_ELEMENTS (attr_types),
		                      NULL, autoselect_object_details, actx);
	}

	actx->enum_done = TRUE;
	g_list_free_full (objects, g_object_unref);

	if (actx->pending == 0)
		autoselect_finish (actx);
}

static void
autoselect_session_opened (GObject *obj, GAsyncResult *res, gpointer user_data)
{
	AutoselectCtx *actx = user_data;
	GckSession *session;
	GckEnumerator *enm;
	GError *error = NULL;

	session = gck_slot_open_session_finish (actx->slot, res, &error);
	if (!session) {
		g_clear_error (&error);
		autoselect_ctx_free (actx);
		return;
	}
	actx->session = session;

	enm = gck_session_enumerate_objects (session, gck_attributes_new_empty (GCK_INVALID));
	gck_enumerator_next_async (enm, -1, NULL, autoselect_next_object, actx);
}

static void
autoselect_from_combo_model (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);
	GtkTreeModel *model;
	GtkTreeIter iter;
	GckSlot *the_slot = NULL;
	guint token_count = 0;
	gboolean valid;
	AutoselectCtx *actx;

	/* Уже что-то выбрано — не перетираем (защита от гонок/повторов). */
	if (priv->uri)
		return;

	/* Переиспользуем слоты, уже отфильтрованные и сложенные в модель
	 * комбобокса функцией modules_initialized (is_this_a_slot_nobody_loves,
	 * CKF_TOKEN_INITIALIZED и фильтр OpenSC уже применены там). */
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (priv->button));
	for (valid = gtk_tree_model_get_iter_first (model, &iter);
	     valid;
	     valid = gtk_tree_model_iter_next (model, &iter)) {
		GckSlot *slot = NULL;

		gtk_tree_model_get (model, &iter, COLUMN_SLOT, &slot, -1);
		if (!slot)
			continue;             /* разделители и «Select from file…» */
		token_count++;
		if (token_count == 1)
			the_slot = slot;      /* перехватываем ссылку из get */
		else
			g_object_unref (slot);
	}

	/* Ровно один активный токен — иначе пользователь выбирает вручную. */
	if (token_count != 1) {
		g_clear_object (&the_slot);
		return;
	}

	actx = g_slice_new0 (AutoselectCtx);
	actx->button = g_object_ref (button);
	actx->slot = the_slot;            /* владение передано */
	actx->key_ids = g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
	                                       (GDestroyNotify) g_bytes_unref, NULL);
	actx->certs = g_ptr_array_new_with_free_func ((GDestroyNotify) gck_attributes_unref);

	gck_slot_open_session_async (actx->slot, GCK_SESSION_READ_ONLY,
	                             NULL, NULL, autoselect_session_opened, actx);
}

void
nma_cert_chooser_button_autoselect_single_cert (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv;

	g_return_if_fail (NMA_IS_CERT_CHOOSER_BUTTON (button));
	priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	/* Только для комбобокса (PKCS#11); у простой файловой кнопки токенов нет. */
	if (use_simple_button (priv->flags))
		return;
	/* Уже что-то выбрано — не перетираем (защита от гонок/повторов). */
	if (priv->uri)
		return;

	/* Перечисление токенов уже идёт/прошло в modules_initialized —
	 * подключаемся к его результату вместо второго прохода. */
	if (priv->modules_ready)
		autoselect_from_combo_model (button);
	else
		priv->autoselect_requested = TRUE;
}
#else
typedef void GckSlot;
#define GCK_TYPE_SLOT G_TYPE_POINTER

static char *
title_from_pkcs11 (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	g_warning ("PKCS#11 URI, but GCR/GCK support not built in.");
	return g_strdup (priv->uri);
}

static void
select_from_token (NMACertChooserButton *button, GckSlot *slot)
{
	g_assert_not_reached ();
}

static void
initialize_gck_modules (NMACertChooserButton *button)
{
}

static int
use_simple_button (NMACertChooserButtonFlags flags)
{
	return TRUE;
}

void
nma_cert_chooser_button_autoselect_single_cert (NMACertChooserButton *button)
{
}
#endif

static void
update_title (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);
	GtkTreeIter iter;
	GtkTreeModel *model;
	gs_free char *label = NULL;

	if (!priv->uri) {
		label = g_strdup (_("(None)"));
	} else if (g_str_has_prefix (priv->uri, "pkcs11:")) {
		label = title_from_pkcs11 (button);
	} else {
		label = priv->uri;
		if (g_str_has_prefix (label, "file://"))
			label += 7;
		if (g_strrstr (label, "/"))
			label = g_strrstr (label, "/") + 1;
		label = g_strdup (label);
	}

	if (priv->button_label) {
		g_return_if_fail (GTK_IS_BUTTON (priv->button));
		gtk_label_set_text (GTK_LABEL (priv->button_label), label);
	} else if (priv->button) {
		g_return_if_fail (GTK_IS_COMBO_BOX (priv->button));
		model = gtk_combo_box_get_model (GTK_COMBO_BOX (priv->button));

		if (!gtk_tree_model_get_iter_first (model, &iter))
			g_return_if_reached ();

		gtk_list_store_set (GTK_LIST_STORE (model), &iter,
		                    COLUMN_LABEL, label ?: _("(Unknown)"),
		                    -1);
	}
}

static void
select_from_file (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);
	GtkRoot *toplevel;
	GtkWidget *dialog;
	GFile *file;

	toplevel = gtk_widget_get_root (GTK_WIDGET (button));
	if (toplevel && !GTK_IS_WINDOW (toplevel))
		toplevel = NULL;

	dialog = gtk_file_chooser_dialog_new (priv->title,
	                                      (GtkWindow *) toplevel,
	                                      GTK_FILE_CHOOSER_ACTION_OPEN,
	                                      _("Select"), GTK_RESPONSE_ACCEPT,
	                                      _("Cancel"), GTK_RESPONSE_CANCEL,
	                                      NULL);

	if (priv->flags & NMA_CERT_CHOOSER_BUTTON_FLAG_KEY)
		gtk_file_chooser_set_filter (GTK_FILE_CHOOSER (dialog), utils_key_filter ());
	else
		gtk_file_chooser_set_filter (GTK_FILE_CHOOSER (dialog), utils_cert_filter ());

	if (priv->uri) {
		file = g_file_new_for_uri (priv->uri);
		gtk_file_chooser_set_file (GTK_FILE_CHOOSER (dialog), file, NULL);
		g_object_unref (file);
	}
	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_ACCEPT);
	if (nma_gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		if (priv->uri)
			g_free (priv->uri);

		file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (dialog));
		priv->uri = g_file_get_uri (file);
		g_object_unref (file);

		if (priv->pin) {
			g_free (priv->pin);
			priv->pin = NULL;
		}
		priv->remember_pin = FALSE;
		priv->has_matching_key = FALSE;
		update_title (button);
		g_signal_emit_by_name (button, "changed");
	}
	gtk_window_destroy (GTK_WINDOW (dialog));
}

static void
changed (GtkComboBox *combo_box, gpointer user_data)
{
	NMACertChooserButton *self = NMA_CERT_CHOOSER_BUTTON (user_data);
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *label;
	GckSlot *slot;

	if (gtk_combo_box_get_active (combo_box) == 0)
		return;

	gtk_combo_box_popdown (combo_box);
	g_signal_stop_emission_by_name (combo_box, "changed");
	gtk_combo_box_get_active_iter (combo_box, &iter);

	model = gtk_combo_box_get_model (combo_box);
	gtk_tree_model_get (model, &iter,
	                    COLUMN_LABEL, &label,
	                    COLUMN_SLOT, &slot, -1);
	if (slot)
		select_from_token (self, slot);
	else
		select_from_file (self);

	g_free (label);
	g_clear_object (&slot);
	gtk_combo_box_set_active (combo_box, 0);
}

static gboolean
row_separator (GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	gchar *label;
	GckSlot *slot;

	gtk_tree_model_get (model, iter, 0, &label, 1, &slot, -1);
	if (label == NULL && slot == NULL)
		return TRUE;
	g_free (label);
	g_clear_object (&slot);

	return FALSE;
}

static void
create_cert_combo (NMACertChooserButton *self)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (self);
	GtkListStore *model;
	GtkTreeIter iter;
	GtkCellRenderer *cell;

	model = gtk_list_store_new (2, G_TYPE_STRING, GCK_TYPE_SLOT);
	priv->button = gtk_combo_box_new_with_model (GTK_TREE_MODEL (model));
	gtk_widget_set_hexpand (priv->button, TRUE);
	gtk_widget_show (priv->button);
	g_object_unref (model);

	gtk_box_append (GTK_BOX (self), priv->button);

	gtk_combo_box_set_popup_fixed_width (GTK_COMBO_BOX (priv->button), TRUE);
	gtk_combo_box_set_row_separator_func (GTK_COMBO_BOX (priv->button),
	                                      row_separator,
	                                      NULL,
	                                      NULL);

	/* The first entry with current object name. */
	gtk_list_store_insert_with_values (model, &iter, 0,
	                                   COLUMN_LABEL, NULL,
	                                   COLUMN_SLOT, NULL, -1);

	/* The separator and the last entry. The tokens will be added in between. */
	gtk_list_store_insert_with_values (model, &iter, 1,
	                                   COLUMN_LABEL, NULL,
	                                   COLUMN_SLOT, NULL, -1);
	gtk_list_store_insert_with_values (model, &iter, 2,
	                                   COLUMN_LABEL, _("Select from file\342\200\246"),
	                                   COLUMN_SLOT, NULL, -1);

	cell = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (priv->button), cell, FALSE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (priv->button), cell, "text", 0);

	g_signal_connect (priv->button, "changed", (GCallback) changed, self);

	gtk_combo_box_set_active (GTK_COMBO_BOX (priv->button), 0);
	initialize_gck_modules (self);
}

static void
create_file_button (NMACertChooserButton *self)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (self);
	GtkWidget *widget;
	GtkWidget *box;

	gtk_orientable_set_orientation (GTK_ORIENTABLE (self), GTK_ORIENTATION_VERTICAL);
	priv->button = gtk_button_new ();
	gtk_widget_show (priv->button);
	gtk_box_append (GTK_BOX (self), priv->button);
	g_signal_connect_swapped (priv->button, "clicked", (GCallback) select_from_file, self);

	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 1);
	gtk_widget_show (box);
	gtk_button_set_child (GTK_BUTTON (priv->button), box);

	priv->button_label = gtk_label_new (NULL);
	gtk_widget_show (priv->button_label);
	gtk_label_set_ellipsize (GTK_LABEL (priv->button_label), PANGO_ELLIPSIZE_END);
	g_object_set (priv->button_label, "xalign", (gfloat) 0, NULL);
	gtk_widget_set_hexpand (priv->button_label, TRUE);
	gtk_box_append (GTK_BOX (box), priv->button_label);

	widget = gtk_image_new_from_icon_name ("document-open-symbolic");
	gtk_widget_show (widget);
	gtk_box_append (GTK_BOX (box), widget);
}

static void
constructed (GObject *object)
{
	NMACertChooserButton *self = NMA_CERT_CHOOSER_BUTTON (object);
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (self);

        G_OBJECT_CLASS (nma_cert_chooser_button_parent_class)->constructed (object);

	if (use_simple_button (priv->flags))
		create_file_button (self);
	else
		create_cert_combo (self);

	update_title (self);
}

static void
set_property (GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (object);

	switch (property_id) {
	case PROP_FLAGS:
		priv->flags = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (object);

	nm_clear_g_free (&priv->title);
	nm_clear_g_free (&priv->uri);
	nm_clear_g_free (&priv->pin);

        G_OBJECT_CLASS (nma_cert_chooser_button_parent_class)->dispose (object);
}

static gboolean
mnemonic_activate (GtkWidget *widget, gboolean group_cycling)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (widget);

	return gtk_widget_mnemonic_activate (priv->button, group_cycling);
}

static void
nma_cert_chooser_button_class_init (NMACertChooserButtonClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMACertChooserButtonPrivate));

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->set_property = set_property;
	widget_class->mnemonic_activate = mnemonic_activate;

	g_signal_new ("changed",
	              G_OBJECT_CLASS_TYPE(object_class),
	              G_SIGNAL_RUN_LAST,
	              0, NULL, NULL,
	              NULL,
	              G_TYPE_NONE, 0);

        g_object_class_install_property (object_class, PROP_FLAGS,
		g_param_spec_uint ("flags", NULL, NULL,
		                   NMA_CERT_CHOOSER_BUTTON_FLAG_NONE,
		                     NMA_CERT_CHOOSER_BUTTON_FLAG_KEY
		                   | NMA_CERT_CHOOSER_BUTTON_FLAG_PEM,
		                   NMA_CERT_CHOOSER_BUTTON_FLAG_NONE,
		                     G_PARAM_WRITABLE
		                   | G_PARAM_CONSTRUCT_ONLY
		                   | G_PARAM_STATIC_STRINGS));
}

static void
nma_cert_chooser_button_init (NMACertChooserButton *self)
{
}

/**
 * nma_cert_chooser_button_set_title:
 * @button: the #NMACertChooserButton instance
 * @title: the title of the token or file chooser dialogs
 *
 * Set the title of file or PKCS\#11 object chooser dialogs.
 */
void
nma_cert_chooser_button_set_title (NMACertChooserButton *button, const gchar *title)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	if (priv->title)
		g_free (priv->title);
	priv->title = g_strdup (title);
}

/**
 * nma_cert_chooser_button_get_uri:
 * @button: the #NMACertChooserButton instance
 *
 * Obtain the URI of the selected obejct -- either of
 * "pkcs11" or "file" scheme.
 *
 * Returns: the URI or %NULL if none was selected.
 */
const gchar *
nma_cert_chooser_button_get_uri (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	return priv->uri;
}

/**
 * nma_cert_chooser_button_set_uri:
 * @button: the #NMACertChooserButton instance
 * @uri: the URI
 *
 * Set the chosen URI to given string.
 */
void
nma_cert_chooser_button_set_uri (NMACertChooserButton *button, const gchar *uri)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	if (priv->uri)
		g_free (priv->uri);
	priv->uri = g_strdup (uri);
	priv->has_matching_key = FALSE;
	update_title (button);
}

/**
 * nma_cert_chooser_button_set_uri_autoselected:
 * @button: the #NMACertChooserButton instance
 * @uri: the PKCS\#11 URI of the certificate to select
 * @has_matching_key: whether the token carries a key with a matching CKA_ID
 *
 * Sets the chosen URI as if it had been picked by the user from a token and
 * emits "changed", so that the consumer (NMACertChooser) runs its private key
 * autodetection. Unlike nma_cert_chooser_button_set_uri(), this preserves the
 * @has_matching_key flag and notifies listeners.
 */
void
nma_cert_chooser_button_set_uri_autoselected (NMACertChooserButton *button,
                                              const gchar *uri,
                                              gboolean has_matching_key)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	if (priv->uri)
		g_free (priv->uri);
	priv->uri = g_strdup (uri);
	priv->has_matching_key = has_matching_key;

	/* PIN вводится отдельно в модалке апплета, не запоминаем его здесь. */
	nm_clear_g_free (&priv->pin);
	priv->remember_pin = FALSE;

	update_title (button);

	/* Эмитим "changed" — это запускает cert_changed_cb в NMACertChooser,
	 * который выполняет автоподстановку приватного ключа. */
	g_signal_emit_by_name (button, "changed");
}

/**
 * nma_cert_chooser_button_get_id:
 * @button: the #NMACertChooserButton instance
 *
 * Gets the certificate id (length and value) by the passed uri.
 *
 * Returns: NULL or the certificate id memory chunk [length + value]
 * The size of the length part is sizeof(GckAttribute::length)
 */
gchar *
nma_cert_chooser_button_get_id (NMACertChooserButton *button, const gchar *uri)
{
	GckUriData *data;
	gchar* id_chunk;
	const GckAttribute *id = NULL;
	GError *error = NULL;

	data = gck_uri_parse (uri, GCK_URI_FOR_OBJECT_ON_TOKEN, &error);
	if (!data)
	{	
		g_warning ("Bad URI '%s': %s\n", uri, error->message);
		g_error_free (error);
		return NULL;
	}

	id = gck_attributes_find (data->attributes, CKA_ID);
	if (!id || !id->value || !id->length) 
	{
		gck_uri_data_free (data);
		return NULL;
	}

	id_chunk = (gchar *)g_malloc(sizeof(id->length) + id->length);
	memcpy(id_chunk, &id->length, sizeof(id->length));
	memcpy(id_chunk + sizeof(id->length), id->value, id->length);

	gck_uri_data_free (data);

	return id_chunk;
}

/**
 * nma_cert_chooser_button_derive_key_uri:
 * @button: the #NMACertChooserButton instance
 * @cert_uri: a PKCS\#11 URI of a certificate on a token
 *
 * Derives a private key URI from a certificate URI by keeping the token
 * identification and the object id (CKA_ID), assuming the private key and
 * the certificate share the same id.
 *
 * Returns: the derived key URI, or %NULL if @cert_uri is not a PKCS\#11
 *   URI or carries no id.
 */
gchar *
nma_cert_chooser_button_derive_key_uri (NMACertChooserButton *button, const gchar *cert_uri)
{
#if WITH_GCR
	GckUriData *data;
	GckBuilder *builder;
	GckUriData key_uri_data = { 0, };
	const GckAttribute *id;
	gchar *key_uri = NULL;
	GError *error = NULL;

	if (!cert_uri)
		return NULL;

	data = gck_uri_parse (cert_uri, GCK_URI_FOR_OBJECT_ON_TOKEN, &error);
	if (!data) {
		g_warning ("Bad URI '%s': %s\n", cert_uri, error ? error->message : "(unknown)");
		g_clear_error (&error);
		return NULL;
	}

	id = gck_attributes_find (data->attributes, CKA_ID);
	if (!id || !id->value || !id->length) {
		gck_uri_data_free (data);
		return NULL;
	}

	/* Keep only the id; combined with the token info this yields a URI
	 * that matches the private key with the same id on the token. */
	builder = gck_builder_new (GCK_BUILDER_NONE);
	gck_builder_add_only (builder, data->attributes, CKA_ID, GCK_INVALID);
	key_uri_data.attributes = gck_builder_end (builder);
	key_uri_data.token_info = data->token_info;
	key_uri = gck_uri_data_build (&key_uri_data, GCK_URI_FOR_OBJECT_ON_TOKEN);

	gck_attributes_unref (key_uri_data.attributes);
	gck_uri_data_free (data);

	return key_uri;
#else
	return NULL;
#endif
}


/**
 * nma_cert_chooser_button_get_pin:
 * @button: the #NMACertChooserButton instance
 *
 * Obtain the PIN that was used to unlock the token.
 *
 * Returns: the PIN, %NULL if the token was not logged into or an emtpy
 *   string ("") if the protected authentication path was used.
 */
gchar *
nma_cert_chooser_button_get_pin (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	return g_strdup (priv->pin);
}

/**
 * nma_cert_chooser_button_get_remember_pin:
 * @button: the #NMACertChooserButton instance
 *
 * Obtain the value of the "Remember PIN" checkbox during the token login.
 *
 * Returns: TRUE if the user chose to remember the PIN, FALSE
 *   if not or if the tokin was not logged into at all.
 */
gboolean
nma_cert_chooser_button_get_remember_pin (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	return priv->remember_pin;
}

/**
 * nma_cert_chooser_button_get_has_matching_key:
 * @button: the #NMACertChooserButton instance
 *
 * Returns whether the most recent selection was made from a PKCS\#11 token
 * and that token carries a key object (private or public) whose CKA_ID
 * matches the selected certificate.
 *
 * Returns: TRUE if a matching key was observed on the token;
 */
gboolean
nma_cert_chooser_button_get_has_matching_key (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = NMA_CERT_CHOOSER_BUTTON_GET_PRIVATE (button);

	return priv->has_matching_key;
}

/**
 * nma_cert_chooser_button_new:
 * @flags: the flags configuring the behavior of the chooser dialogs
 *
 * Creates the new button that can select certificates from
 * files or PKCS\#11 tokens.
 *
 * Returns: the newly created #NMACertChooserButton
 */
GtkWidget *
nma_cert_chooser_button_new (NMACertChooserButtonFlags flags)
{
	return g_object_new (NMA_TYPE_CERT_CHOOSER_BUTTON, "flags", flags, NULL);
}
