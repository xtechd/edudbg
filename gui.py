import dearpygui.dearpygui as dpg
from edudbg import *

dpg.create_context()

def file_selected_callback(sender, app_data):
    if app_data['selections']:
        file_path = list(app_data['selections'].values())[0]
        dpg.set_value("selected_file_text", f"Fichier sélectionné : {file_path}")
        with open(file_path, 'r', encoding="utf-8") as f:
            content = f.read()
        dpg.set_value("code_editor", content)
        dpg.set_value("debug_console", f"[INFO] Fichier chargé : {file_path}\n")

def add_breakpoint():
    ligne = dpg.get_value("breakpoint_input")
    current = dpg.get_item_configuration("breakpoints_list")["items"]
    if f"Ligne {ligne}" not in current:
        updated = current + [f"Ligne {ligne}"]
        dpg.configure_item("breakpoints_list", items=updated)

def get_selected_breakpoint_index():
    selected = dpg.get_value("breakpoints_list")
    items = dpg.get_item_configuration("breakpoints_list")["items"]
    try:
        return items.index(selected)
    except ValueError:
        return None

def remove_selected_breakpoint():
    idx = get_selected_breakpoint_index()
    if idx is not None:
        items = dpg.get_item_configuration("breakpoints_list")["items"]
        del items[idx]
        dpg.configure_item("breakpoints_list", items=items)
        if items:
            dpg.set_value("breakpoints_list", items[0])
        else:
            dpg.set_value("breakpoints_list", "")

def copy_selected_breakpoint():
    bp = dpg.get_value("breakpoints_list")
    if bp:
        dpg.set_value("debug_console", f"[Copie fictive] Contenu : {bp}\n")

def jump_to_line():
    bp = dpg.get_value("breakpoints_list")
    if bp:
        dpg.set_value("debug_console", f"[Jump] Tu veux aller à {bp} ?\n")

def start_debug():
    current_file = dpg.get_value("selected_file_text").replace("Fichier sélectionné : ", "")
    dpg.set_value("debug_console", f"[DEBUG] Envoi du fichier : {current_file}\nAnalyse en cours...\n")
    dpg.set_value("registers_view", "EAX: 0x0040\nEBX: 0x0020\n...")
    dpg.set_value("stack_view", "0x1000: push eax\n0x1002: call func\n...")
    dpg.set_value("memory_view", "0x2000: 41 42 43 44\n0x2004: 45 46 47 48")

def show_about(): dpg.configure_item("about_popup", show=True)
def show_docs(): dpg.configure_item("doc_popup", show=True)
def show_settings(): dpg.configure_item("settings_popup", show=True)

with dpg.file_dialog(directory_selector=False, show=False, callback=file_selected_callback, file_count=1, tag="file_dialog_tag", width=700, height=400):
    dpg.add_file_extension(".py", color=(0, 255, 0, 255))
    dpg.add_file_extension(".*")

with dpg.window(label="À propos", modal=True, show=False, tag="about_popup", no_resize=True, width=400, height=200):
    dpg.add_text("a venir")
    dpg.add_button(label="Fermer", callback=lambda: dpg.configure_item("about_popup", show=False))

with dpg.window(label="Documentation", modal=True, show=False, tag="doc_popup", no_resize=True, width=500, height=300):
    dpg.add_text("a venir")
    dpg.add_button(label="Fermer", callback=lambda: dpg.configure_item("doc_popup", show=False))

with dpg.window(label="Options", modal=True, show=False, tag="settings_popup", no_resize=True, width=500, height=300):
    dpg.add_text("a venir")
    dpg.add_button(label="Fermer", callback=lambda: dpg.configure_item("settings_popup", show=False))

with dpg.viewport_menu_bar():
    with dpg.menu(label="Fichier"):
        dpg.add_menu_item(label="Quitter", callback=lambda: dpg.stop_dearpygui())
    with dpg.menu(label="Options"):
        dpg.add_menu_item(label="Préférences", callback=show_settings)
    with dpg.menu(label="Documentation"):
        dpg.add_menu_item(label="Voir la doc", callback=show_docs)
    with dpg.menu(label="À propos"):
        dpg.add_menu_item(label="À propos", callback=show_about)

with dpg.window(tag="main_window", no_title_bar=True, no_move=True, no_collapse=True, no_close=True, autosize=False):
    with dpg.group(horizontal=True):
        with dpg.child_window(width=250, autosize_y=True, border=True):
            dpg.add_text("Breakpoints")
            dpg.add_separator()
            dpg.add_listbox(items=[], num_items=6, tag="breakpoints_list")
            with dpg.popup(parent="breakpoints_list", mousebutton=dpg.mvMouseButton_Right, tag="breakpoint_popup"):
                dpg.add_text("Actions sur le breakpoint")
                dpg.add_separator()
                dpg.add_button(label="Supprimer", callback=remove_selected_breakpoint)
                dpg.add_button(label="Aller à la ligne", callback=jump_to_line)
                dpg.add_button(label="Copie fictive", callback=copy_selected_breakpoint)

            dpg.add_input_int(tag="breakpoint_input", min_value=1)
            dpg.add_button(label="Ajouter Breakpoint", callback=add_breakpoint)
            dpg.add_text("Fonctions")
            dpg.add_separator()
            dpg.add_listbox(items=["main()", "fonction_test()"], tag="functions_list")

        with dpg.group():
            dpg.add_text()
            dpg.add_button(label="Sélectionner un fichier Python", callback=lambda: dpg.show_item("file_dialog_tag"))
            dpg.add_text("", tag="selected_file_text")
            dpg.add_button(label="Analyser / Lancer Debug", callback=start_debug)
            dpg.add_input_text(tag="code_editor", multiline=True, readonly=True, width=600, height=300)
            dpg.add_separator()
            dpg.add_text("Console de Debug")
            dpg.add_input_text(tag="debug_console", multiline=True, readonly=True, width=600, height=100)

        with dpg.child_window(width=-1, autosize_y=True, border=True):
            dpg.add_text("Registres")
            dpg.add_input_text(tag="registers_view", multiline=True, readonly=True, width=-1, height=100)
            dpg.add_separator()
            dpg.add_text("Stack")
            dpg.add_input_text(tag="stack_view", multiline=True, readonly=True, width=-1, height=100)
            dpg.add_separator()
            dpg.add_text("Mémoire")
            dpg.add_input_text(tag="memory_view", multiline=True, readonly=True, width=-1, height=100)

dpg.create_viewport(title="Debugger", width=1280, height=720)
dpg.setup_dearpygui()

def resize_callback(sender, app_data):
    width = dpg.get_viewport_client_width()
    height = dpg.get_viewport_client_height()
    dpg.set_item_width("main_window", width)
    dpg.set_item_height("main_window", height)

dpg.set_viewport_resize_callback(resize_callback)
resize_callback(None, None)

dpg.set_primary_window("main_window", True)
dpg.show_viewport()
dpg.start_dearpygui()
dpg.destroy_context()