import ttkbootstrap as tk
from tkinter import filedialog
from ttkbootstrap.dialogs import Messagebox
import locker as locker
from PIL import Image, ImageTk
from caesar import caesar_cipher

encryptor = locker.Cs404_locker()  # Calls an instance of the 404 locker class
"""
TODO add Caesar Cypher tab
TODO add Cypher scrambler tab for text files
TODO Fix tab 2 to make it prettier
TODO make labels clear after job is executed
"""


class locker_404:
    def __init__(
        self, root
    ):  # Here are the parameters for the window contained in a class
        root.title("404 Cryptography Demo")
        root.geometry("800x400")
        root.maxsize(800, 400)
        self.checkbox_var = (
            tk.BooleanVar()
        )  # The value of the checkbox in tab 3 Encryption
        self.decrypt_checkbox_var = (
            tk.BooleanVar()
        )  # Value of checkbox in tab 4 Decryption
        self.key_filepath = None  # Filepath of key selected
        self.decrypt_key_filepath = None  # Decrypt key filepath
        self.key_name = None  # Name of key in tab 2 Key creation
        self.iconphoto = ""
        self.file_to_encrypt = None  # Selected file to encrypt in tab 3
        self.selected_key_label = None
        self.file_to_decrypt = None
        self.caesar_shift = 0
        self.text_out = ""

        # Creates the main frame for content
        frame = tk.Frame(root, width=800, height=400, borderwidth=2)
        frame.pack(expand=3, fill="both")

        # Creates the tabs for different pages & adds them to the menu
        tabControl = tk.Notebook(frame, style="danger")
        tab1 = tk.Frame(tabControl)
        tab2 = tk.Frame(tabControl)
        tab3 = tk.Frame(tabControl)
        tab4 = tk.Frame(tabControl)
        tab5 = tk.Frame(tabControl)
        tab6 = tk.Frame(tabControl)
        tab9 = tk.Frame(tabControl)
        # Sets the name of the tab
        tabControl.add(tab1, text="Main")
        tabControl.add(tab2, text="Key Gen")
        tabControl.add(tab3, text="Encrypt")
        tabControl.add(tab4, text="Decrypt")
        tabControl.add(tab5, text="Caesar Cypher")
        tabControl.add(tab6, text="Cypher Output")
        tabControl.add(tab9, text="About")
        """
        Tab 1 Begins here
        """
        # Places the tab in the root frame with grid
        tabControl.pack(expand=1, fill="both")
        tk.Label(
            tab1,
            text="This is a demo of how cryptography works created for the CS404 club",
            font=("Helvetica", 18),
        ).grid(column=0, row=0, padx=30, pady=30)
        # Tab 1 Frame
        tab_frame_1 = tk.Frame(tab1, width=60, height=90, borderwidth=2)
        tab_frame_1.grid(row=0, column=0)
        # Tab 1 text frame
        text_frame_1 = tk.Text(
            tab_frame_1, wrap="word", width=60, height=60, font="Helvetica, 18"
        )
        text_frame_1.grid(row=1, column=0)
        # Tab 1 Text fram contents
        tab_info_1 = "This is an application created to show how encryption works on files in a system. Created only for educational purposes for the CS404 Club.Be aware improper use of this tool may lead to data loss or worse, use at your own risk on files that are important. This should not be used to keep files safe."
        text_frame_1.insert("1.0", tab_info_1)
        text_frame_1.config(state="disabled")
        # Image Display
        image = Image.open("images/CS404.png")
        image = image.resize((159, 211), Image.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        image_label = tk.Label(tab_frame_1, image=photo)
        image_label.grid(row=0, column=0)
        image_label.image = photo
        """
        Tab 2 Key generation
        """
        # Label for tab 2 desc
        tk.Label(
            tab2,
            text="Select a folder for the key and set a name",
            font="Helvetica, 18",
            borderwidth=2,
        ).grid(column=0, row=0, columnspan=3, sticky="nswe", padx=10, pady=10)
        # Key generation button
        key_creation = tk.Button(
            tab2, text="Generate a Key", command=self.make_key, style="danger"
        )
        key_creation.grid(column=1, row=4, sticky="nswe", padx=10, pady=10)
        # Button for selecting filepath
        open_button = tk.Button(
            tab2,
            text="Select Folder for Key",
            command=self.open_file_dialog,
            style="danger",
        )
        open_button.grid(column=0, row=2, padx=10, pady=10, sticky="nsew")
        # Filename entry label
        tk.Label(
            tab2,
            text="Name the key:",
            font="Helvetica, 18",
            borderwidth=2,
        ).grid(column=0, row=3, columnspan=2, sticky="nswe", padx=10, pady=10)
        # Entry for Filename
        self.filename_entry = tk.Entry(tab2, style="danger")
        self.filename_entry.grid(column=1, row=3, padx=10, pady=10, sticky="nsew")
        self.filename_entry.insert(0, "")

        # Tab 2 text frame
        text_frame_2 = tk.Text(
            tab2, wrap="word", width=60, height=60, font="Helvetica, 18"
        )
        text_frame_2.grid(
            row=6, column=0, columnspan=3, sticky="nsew", padx=10, pady=10
        )

        # Frame for label filepath key
        self.key_folder = tk.Frame(
            tab2, width=80, height=70, borderwidth=2, relief="sunken"
        )
        self.key_folder.grid(row=2, column=1, padx=10, pady=10, sticky="nsew")
        # Label to show file to be decrypted
        self.key_folder_show = tk.Label(
            self.key_folder, text=self.key_filepath, width=70
        )
        self.key_folder_show.grid(column=0, row=2, sticky="nsew")

        # Tab 2 Text frame contents
        tab_info_2 = "This creates a 32 bit AES-128 key, it is used in the other tabs with an algorythm to encrypt data into cypertext. It is important to keep this file as you will NOT be able to unencrypt a file if you lose this key. So keep this in a safe place if you want to unencrypt the data you encrypted."
        text_frame_2.insert("1.0", tab_info_2)
        text_frame_2.config(state="disabled")
        """
        Tab 3 encryption
        """
        # Tab 3 Encryption
        encryption_frame = tk.Frame(tab3, width=80, height=90, borderwidth=2)
        encryption_frame.grid(column=0, row=0, sticky="nsew")

        # Title label
        encryption_frame_title = tk.Label(
            encryption_frame,
            borderwidth=2,
            text="File encryption with a key",
            font="Helvetica, 18",
        )
        encryption_frame_title.grid(row=0, column=2, sticky="nsew", columnspan=4)

        # Button for selecting filepath
        open_key_button = tk.Button(
            encryption_frame, text="Select a Key", command=self.open_key, style="danger"
        )
        open_key_button.grid(
            column=1, row=1, padx=10, pady=10, columnspan=2, sticky="nsew"
        )

        # Frame for label filepath key
        selected_key_labelframe = tk.Frame(
            encryption_frame, width=80, height=70, borderwidth=2, relief="sunken"
        )
        selected_key_labelframe.grid(
            row=1, column=3, padx=10, pady=10, columnspan=2, sticky="nsew"
        )
        # Label to show key selected
        self.selected_key = tk.Label(
            selected_key_labelframe, text=self.decrypt_key_filepath, width=70
        )
        self.selected_key.grid(column=2, row=2, sticky="nsew")
        # Button for selecting file to be encrypted
        open_encrypt_file = tk.Button(
            encryption_frame,
            text="Select a file",
            command=self.open_file,
            style="danger",
        )
        open_encrypt_file.grid(
            column=1, row=3, padx=10, pady=10, columnspan=2, sticky="nsew"
        )

        # Frame for label filepath key
        selected_file_label_frame = tk.Frame(
            encryption_frame, width=80, height=70, borderwidth=2, relief="sunken"
        )
        selected_file_label_frame.grid(row=3, column=3, padx=10, pady=10, sticky="nsew")
        # Label to show file to be encrypted
        self.file_selected = tk.Label(
            selected_file_label_frame, text=self.file_to_encrypt, width=70
        )
        self.file_selected.grid(column=4, row=4, sticky="nsew")
        # Create the checkbox
        checkbox = tk.Checkbutton(
            encryption_frame,
            text="I agree",
            variable=self.checkbox_var,
            command=self.checkbox_var.get(),
        )
        checkbox.grid(column=2, row=4, padx=10, pady=10, sticky="nsew")

        # Button for starting encryption
        call_encrypt = tk.Button(
            encryption_frame,
            text="Encrypt",
            command=self.encrypt,
            style="danger",
        )
        call_encrypt.grid(
            column=3, row=4, padx=10, pady=10, columnspan=2, sticky="nsew"
        )
        warning = "This file is not important"
        warning_label = tk.Label(
            encryption_frame, text=warning, width=30, font="Helvetica, 12"
        )
        warning_label.grid(column=1, row=4, sticky="nse")

        # Tab 3 text frame
        text_frame_3 = tk.Text(
            encryption_frame, wrap="word", width=60, height=60, font="Helvetica, 18"
        )
        text_frame_3.grid(row=6, column=1, columnspan=3, sticky="nsew")
        # Tab 3 Text frame contents
        tab_info_3 = "This uses a 32 bit AES-128 key created by the previous tab to convert a file into cyphertext making it unreadable, any file this program encrypts has their extension automatically changed to .404 Not recommended to be used on important files, this is just a demonstration of how symmetric key encryption works. Use on important data at your own risk."
        text_frame_3.insert("1.0", tab_info_3)
        text_frame_3.config(state="disabled")
        """
        Tab 4 Decryption
        """
        # Tab 4 Decryption
        decryption_frame = tk.Frame(tab4, width=80, height=90, borderwidth=2)
        decryption_frame.grid(column=0, row=0, sticky="nsew")

        # Title label
        dacryption_frame_title = tk.Label(
            decryption_frame,
            borderwidth=2,
            text="File decryption with a key",
            font="Helvetica, 18",
        )
        dacryption_frame_title.grid(row=0, column=2, sticky="nsew", columnspan=4)

        # Button for selecting filepath
        open_key_button = tk.Button(
            decryption_frame,
            text="Select a Key",
            command=self.decrypt_open_key,
            style="danger",
        )
        open_key_button.grid(
            column=1, row=1, padx=10, pady=10, columnspan=2, sticky="nsew"
        )

        # Frame for label filepath key
        decryption_selected_key_labelframe = tk.Frame(
            decryption_frame, width=80, height=70, borderwidth=2, relief="sunken"
        )
        decryption_selected_key_labelframe.grid(
            row=1, column=3, padx=10, pady=10, columnspan=2, sticky="nsew"
        )
        # Label to show key selected
        self.decryption_selected_key = tk.Label(
            decryption_selected_key_labelframe, text=self.file_to_decrypt, width=70
        )
        self.decryption_selected_key.grid(column=2, row=2, sticky="nsew")
        # Button for selecting file to be encrypted
        decrypt_open_encrypt_file = tk.Button(
            decryption_frame,
            text="Select a file",
            command=self.open_file_decrypt,
            style="danger",
        )
        decrypt_open_encrypt_file.grid(
            column=1, row=3, padx=10, pady=10, columnspan=2, sticky="nsew"
        )

        # Frame for label filepath key
        self.decrypt_selected_file_label_frame = tk.Frame(
            decryption_frame, width=80, height=70, borderwidth=2, relief="sunken"
        )
        self.decrypt_selected_file_label_frame.grid(
            row=3, column=3, padx=10, pady=10, sticky="nsew"
        )
        # Label to show file to be decrypted
        self.decrypt_file_selected = tk.Label(
            self.decrypt_selected_file_label_frame, text=self.file_to_decrypt, width=70
        )
        self.decrypt_file_selected.grid(column=4, row=4, sticky="nsew")
        # Create the checkbox
        checkbox = tk.Checkbutton(
            decryption_frame,
            text="I agree",
            variable=self.decrypt_checkbox_var,
            command=self.decrypt_checkbox_var.get(),
        )
        checkbox.grid(column=2, row=4, padx=10, pady=10, sticky="nsew")

        # Button for starting encryption
        call_decrypt = tk.Button(
            decryption_frame,
            text="Decrypt",
            command=self.decrypt,
            style="danger",
        )
        call_decrypt.grid(
            column=3, row=4, padx=10, pady=10, columnspan=2, sticky="nsew"
        )
        warning = "This file is not important"
        warning_label = tk.Label(
            decryption_frame, text=warning, width=30, font="Helvetica, 12"
        )
        warning_label.grid(column=1, row=4, sticky="nse")

        # Tab 4 text frame
        text_frame_4 = tk.Text(
            decryption_frame, wrap="word", width=60, height=60, font="Helvetica, 18"
        )
        text_frame_4.grid(row=6, column=1, columnspan=3, sticky="nsew")
        # Tab 4 Text frame contents
        tab_info_4 = "This uses a 32 bit AES-128 key created in the second tab to decrypt files from cyphertext. It will only work with files created with this program."
        text_frame_4.insert("1.0", tab_info_4)
        text_frame_4.config(state="disabled")

        """
        Tab 5 Caesar Cypher
        """
        # Tab 5 Frame
        caesar = tk.Frame(tab5)
        caesar.grid(row=0, column=0)
        # Tab 5 Text Frame
        caesar_frame = tk.Label(
            caesar,
            text="A Caesar Cypher, output in next tab.",
            wraplength=600,
            font=("Helvetica", 18),
        )
        caesar_frame.grid(row=0, column=0, sticky="nsw", padx=10, pady=10)

        # Create a frame to hold both the Text widget and the Scrollbar
        text_frame = tk.Frame(caesar)
        text_frame.grid(row=4, column=0, sticky="nswe", padx=10, pady=10, columnspan=3)
        # Create the Input Text widget
        self.caesar_text_frame1 = tk.Text(
            text_frame, wrap="word", width=83, height=12, font=("Helvetica", 12)
        )  # Adjust height for better fit
        self.caesar_text_frame1.grid(row=0, column=0, sticky="nswe")

        # Create the Scrollbar and link it to the Text widget
        scrollbar = tk.Scrollbar(
            text_frame, orient="vertical", command=self.caesar_text_frame1.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Configure the Text widget to use the Scrollbar
        self.caesar_text_frame1.configure(yscrollcommand=scrollbar.set)

        # Make the text_frame grid expand as needed
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)

        # Encrypt Button
        caesar_button = tk.Button(
            caesar, text="Encrypt", command=self.caesar_encrypt, style="danger"
        )
        caesar_button.grid(column=2, row=2, sticky="nswe", padx=10, pady=10)

        # Paste Button
        caesar_button = tk.Button(
            caesar, text="Paste", command=self.paste_text, style="danger"
        )
        caesar_button.grid(column=1, row=0, sticky="nswe", padx=10, pady=10)

        # Clear Button
        caesar_button = tk.Button(caesar, text="Clear", command=self.rm, style="danger")
        caesar_button.grid(column=2, row=0, sticky="nswe", padx=10, pady=10)

        # Function to update the label with the current scale value
        def update_label(value):
            value_label.config(text=f"Shift Value: {int(round(float(value)))}")
            self.caesar_shift = f"{int(round(float(value)))}"

        scale = tk.Scale(
            caesar, from_=0, to=26, length=300, bootstyle="danger", command=update_label
        )  # Adjust bootstyle as needed
        scale.grid(column=0, row=1)

        value_label = tk.Label(caesar, text="Value: 0", font=("Helvetica", 16))
        value_label.grid(row=2, column=0)

        """
        Tab 6 Caesar Output
        """
        # Tab 6 Frame
        caesar_out = tk.Frame(tab6)
        caesar_out.grid(row=0, column=0)
        # Tab 6 Text Frame
        caesar_out_frame = tk.Label(
            caesar_out,
            text="Output of Caesar Cypher.",
            wraplength=600,
            font=("Helvetica", 18),
        )
        caesar_out_frame.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)

        # Create a frame to hold both the Text widget and the Scrollbar
        text_frame_out = tk.Frame(caesar_out)
        text_frame_out.grid(
            row=1, column=0, sticky="nswe", padx=10, pady=10, columnspan=3
        )
        # Create the Text widget
        self.caesar_text_frame2 = tk.Text(
            text_frame_out,
            wrap="word",
            width=83,
            height=15,
            font=("Helvetica", 12),
        )  # Adjust height for better fit
        self.caesar_text_frame2.grid(row=1, column=0, sticky="nswe")

        # Create the Scrollbar and link it to the Text widget
        scrollbar2 = tk.Scrollbar(
            text_frame_out, orient="vertical", command=self.caesar_text_frame2.yview
        )
        scrollbar2.grid(row=1, column=1, sticky="ns")

        # Configure the Text widget to use the Scrollbar
        self.caesar_text_frame2.configure(yscrollcommand=scrollbar2.set)
        self.caesar_text_frame2.configure(state="disabled")

        # Make the text_frame grid expand as needed
        self.caesar_text_frame2.grid_rowconfigure(0, weight=1)
        self.caesar_text_frame2.grid_columnconfigure(0, weight=1)

        # Copy Button
        caesar_button = tk.Button(
            caesar_out, text="Copy", command=self.copy_text, style="danger"
        )
        caesar_button.grid(column=1, row=0, sticky="nswe", padx=10, pady=10)

        """
        Key make function
        """

    # def for button to make an encryption key
    # Needs two parameters for input, a filepath to place the key and a name for the key
    def make_key(self):
        self.key_name = self.filename_entry.get()
        if self.key_filepath and self.key_name is None:
            Messagebox.show_error(
                "Please select a folder and enter a name for the key",
                title="Error no folder & name",
                alert=True,
            )
            return
        if self.key_name is None or self.key_name == "":
            Messagebox.show_error(
                "Please enter a name for the key", title="No name Error", alert=True
            )
            return
        if self.key_filepath is None:
            Messagebox.show_error(
                "Please select a folder to save the key in",
                title="No folder Error",
                alert=True,
            )
            return
        if self.key_filepath and self.key_name is not None:
            encryptor.generate_key(self.key_filepath, self.key_name)
            Messagebox.show_info(
                f"A key {self.key_name} Has been created at {self.key_filepath}.404key",
                title="Key Creation successful",
            )
            self.key_filepath = None
            self.key_name = None
            self.key_folder_show.config(text="No folder Selected")
            self.filename_entry.delete(0, tk.END)

    """
    Encryption Function
    """

    # This is the def to encrypt a file using a previously generated key
    def encrypt(self):
        try:
            # If there is no file selected
            if self.file_to_encrypt is None:
                Messagebox.show_error(
                    "Please select a file to encrypt", title="No file Error", alert=True
                )
                return
            # If no key is selected
            if self.decrypt_key_filepath is None:
                Messagebox.show_error(
                    "Please select a decryption key", title="No key Error", alert=True
                )
                return
            # If both are present
            if (
                self.decrypt_key_filepath is not None
                and self.file_to_encrypt is not None
            ):
                if self.checkbox_var.get():
                    self.start_encrypt(self.file_to_encrypt, self.decrypt_key_filepath)
                    Messagebox.show_info(
                        f"File at {self.file_to_encrypt} has been encrypted with key at {self.decrypt_key_filepath}.",
                        alert=True,
                    )
                    self.decrypt_key_filepath = None
                    self.file_to_encrypt = None
                    self.checkbox_var.set(False)
                    # If checkbox is not marked
                else:
                    Messagebox.show_error(
                        "Please check the checkbox",
                        title="No checkbox error",
                        alert=True,
                    )
                    return
        except TypeError:
            print("Not Working")

    """
    Decryption function
    """

    # This is the def to encrypt a file using a previously generated key
    def decrypt(self):
        # If there is no file selected
        if self.file_to_decrypt is None:
            Messagebox.show_error(
                "Please select a file to decrypt", title="No file Error", alert=True
            )
            return
        # If no key is selected
        if self.decrypt_key_filepath is None:
            Messagebox.show_error(
                "Please select a decryption key", title="No key Error", alert=True
            )
            return
        # If both are present
        if self.decrypt_key_filepath is not None and self.file_to_decrypt is not None:
            if self.decrypt_checkbox_var.get():
                self.start_decrypt(self.file_to_decrypt, self.decrypt_key_filepath)
                Messagebox.show_info(
                    f"File at {self.file_to_decrypt} has been decrypted with key at {self.decrypt_key_filepath}.",
                    alert=True,
                )
                self.decrypt_key_filepath = None
                self.file_to_decrypt = None
                self.decrypt_checkbox_var.set(False)
                # If checkbox is not marked
            else:
                Messagebox.show_error(
                    "Please check the checkbox", title="No checkbox error", alert=True
                )
                return

    """
    Caesar cypher function
    """

    def caesar_encrypt(self):
        self.caesar_text_frame2.delete("1.0", tk.END)
        shift = int(self.caesar_shift)
        text = self.caesar_text_frame1.get("1.0", "end-1c")
        if text == "" or None:
            Messagebox.show_error(
                "Please enter some text", title="No text Error", alert=True
            )
            return
        if shift == 0:
            Messagebox.show_error(
                "Please select a shift value", title="No text shift Error", alert=True
            )
            return
        if text and shift:
            # caesar_cipher(text, shift) # update the text frame here with the output of the function
            self.text_out = caesar_cipher(text, shift)
            self.caesar_text_frame2.delete("1.0", tk.END)
            self.caesar_text_frame2.config(state="normal")
            self.caesar_text_frame2.insert("1.0", self.text_out)
            self.caesar_text_frame2.config(state="disabled")
            Messagebox.show_info(
                "Text has been encrypted check out the other tab to see the output",
                title="Text encrypted!",
                alert=True,
            )

    """
    File functions
    """

    # For clearing the Text frame
    def rm(self):
        self.caesar_text_frame1.delete("1.0", tk.END)

    # This is used to open the directory selection dialog and passes the filepath to the next function
    def open_file_dialog(self):
        directory_path = filedialog.askdirectory(title="Select a Directory")
        if directory_path:
            self.key_filepath = directory_path
            self.key_folder_show.config(text=self.key_filepath)

    # This will be used to load a key in for encryption
    def open_key(self):
        key_file_path_selection = filedialog.askopenfilename(
            title="Select a Key file with .404 extension",
            filetypes=[("404 Key Files", "*.404key"), ("All files", "*.*")],
        )
        if key_file_path_selection:
            self.decrypt_key_filepath = key_file_path_selection
            self.selected_key.config(text=key_file_path_selection)

    # This will be used select a file for encryption
    def open_file(self):
        file_selection = filedialog.askopenfilename(
            title="Select a file to encrypt", filetypes=[("All files", "*.*")]
        )
        if file_selection:
            self.file_to_encrypt = file_selection
            self.file_selected.config(text=file_selection)

    """
    Clipboard functions
    """

    def copy_text(self):
        # Enable editing temporarily if the Text widget is disabled
        self.caesar_text_frame2.config(state="normal")

        # Get the text from the Text widget
        text = self.caesar_text_frame2.get(
            "1.0", "end-1c"
        )  # Fetch text up to the last character

        # Clear and set clipboard content
        root.clipboard_clear()  # Clear the clipboard
        root.clipboard_append(text)  # Append new text to the clipboard

        # Show a message that text was copied
        Messagebox.show_info("Text copied to clipboard!", title="Success", alert=True)

        # Return the Text widget to disabled state if needed
        self.caesar_text_frame2.config(state="disabled")

    def paste_text(self):
        try:
            # Get text from the clipboard
            clipboard_text = root.clipboard_get()

            # Insert clipboard text at the current cursor position
            self.caesar_text_frame1.insert(tk.INSERT, clipboard_text)
        except tk.TclError:
            # Handle case where clipboard is empty or contains non-text data
            Messagebox.show_error(
                "Clipboard is empty or contains non-text data.",
                title="Clipboard error",
                alert=True,
            )

    """
    Decryption functions
    """

    # This will be used to load a key in for decryption
    def decrypt_open_key(self):
        key_file_path_selection = filedialog.askopenfilename(
            title="Select a Key file with .404 extension",
            filetypes=[("404 Key Files", "*.404key"), ("All files", "*.*")],
        )
        if key_file_path_selection:
            self.decrypt_key_filepath = key_file_path_selection
            self.decryption_selected_key.config(text=key_file_path_selection)

    # This will be used select a file for decryption
    def open_file_decrypt(self):
        file_selection = filedialog.askopenfilename(
            title="Select a file to encrypt", filetypes=[("All files", "*.*")]
        )
        if file_selection:
            self.file_to_decrypt = file_selection
            self.decrypt_file_selected.config(text=file_selection)

    # Calls the encrypt function outside of init
    def start_encrypt(self, file_name, key_dir):
        try:
            if file_name and key_dir:
                encryptor.encrypt_file(file_name, key_dir)
                self.selected_key.config(text="No Key selected")
                self.file_selected.config(text="No file selected")

        except key_dir is None:
            print("select a file")

    # Calls the decrypt function outside of init
    def start_decrypt(self, file_name, key_dir):
        if file_name and key_dir:
            try:
                encryptor.decrypt_file(file_name, key_dir)
                self.decrypt_file_selected.config(text="No file selected")
            except TypeError as e:
                print(f"error occured{e}")


root = tk.Window(themename="darkly")  # This is the main window
locker_404(root)  # This calls the window with the set parameters to the specific window
root.mainloop()  # Runs the main loop function on the window allowing it to work.
