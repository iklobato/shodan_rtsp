import sqlite3

import streamlit as st
import os


def search_on_db(ip, port):
    conn = sqlite3.connect('rtsp_scanner.db')
    c = conn.cursor()
    c.execute('''
        SELECT * FROM cameras WHERE ip = ? AND port = ?
    '''.strip(), (ip, port))
    result = c.fetchall()
    conn.close()
    return result


def list_images_in_folder(folder_path):
    image_extensions = (".png", ".jpg", ".jpeg", ".gif")
    image_files = [file for file in os.listdir(folder_path) if file.lower().endswith(image_extensions)]
    return image_files


def main():
    st.title("Brazil open cameras")

    folder_path = 'frames'
    current_full_path = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(current_full_path, folder_path)
    image_files = list_images_in_folder(folder_path)

    if not image_files:
        st.error("No images found in the selected folder.")
        return

    for im in image_files:
        ip, port = im.split('_')
        port = port.split('.')[0]
        cam_info = search_on_db(ip, port)
        cidade = cam_info[0][-2]
        st.image(os.path.join(folder_path, im), use_column_width=True, caption=cidade)
        # st.columns([st.image(os.path.join(folder_path, im), use_column_width=True, caption=cidade)])

    # image_path = os.path.join(folder_path, selected_image)
    # image = Image.open(image_path)
    #
    # st.image(image, caption=selected_image, use_column_width=True)


if __name__ == "__main__":
    main()
