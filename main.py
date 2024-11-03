import ttkbootstrap as tk
from tkinter import filedialog
from ttkbootstrap.dialogs import Messagebox
import locker
from PIL import Image, ImageTk

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

        # Creates the main frame for content
        frame = tk.Frame(root, width=800, height=400, borderwidth=2)
        frame.pack(expand=3, fill="both")

        # Creates the tabs for different pages & adds them to the menu
        tabControl = tk.Notebook(frame, style="danger")
        tab1 = tk.Frame(tabControl)
        tab2 = tk.Frame(tabControl)
        tab3 = tk.Frame(tabControl)
        tab4 = tk.Frame(tabControl)
        # Sets the name of the tab
        tabControl.add(tab1, text="Main")
        tabControl.add(tab2, text="Key Gen")
        tabControl.add(tab3, text="Encrypt")
        tabControl.add(tab4, text="Decrypt")
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
        image = Image.open("CS404.png")
        image = image.resize((159, 211), Image.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        image_label = tk.Label(tab_frame_1, image=photo)
        image_label.grid(row=0, column=0)
        image_label.image = photo
        """
        Key generation tab
        """
        # Label for tab 2 desc
        tk.Label(
            tab2,
            text="Select a folder to generate a key and set the name you would like",font="Helvetica, 18"
        ).grid(column=0, row=0, columnspan=3,sticky="nse")
        # Key generation button
        key_creation = tk.Button(
            tab2, text="Generate a Key", command=self.make_key, style="danger"
        )
        key_creation.grid(column=1, row=3,sticky="nswe")
        # Button for selecting filepath
        open_button = tk.Button(
            tab2,
            text="Select Folder for Key",
            command=self.open_file_dialog,
            style="danger",
        )
        open_button.grid(column=0, row=2)
        # Entry for Filename
        self.filename_entry = tk.Entry(tab2, style="danger")
        self.filename_entry.grid(column=1, row=2)
        self.filename_entry.insert(0, "")
        """
        Here is the part where the files are encrypted
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
        Here is tab 4 Decryption
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
        tab_info_4 = "This uses a 32 bit sha256 key to decrypt a .404 file"
        text_frame_4.insert("1.0", tab_info_4)
        text_frame_4.config(state="disabled")

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
            if self.decrypt_key_filepath is not None and self.file_to_encrypt is not None:
                if self.checkbox_var.get():
                    self.start_encrypt(self.file_to_encrypt, self.decrypt_key_filepath)
                    Messagebox.show_info(
                        f"File at {self.file_to_encrypt} has been encrypted with key at {self.decrypt_key_filepath}.",
                        alert=True,
                    )
                    self.decrypt_key_filepath = None
                    self.file_to_encrypt = None
                    # If checkbox is not marked
                else:
                    Messagebox.show_error(
                        "Please check the checkbox", title="No checkbox error", alert=True
                    )
                    return
        except TypeError:
            print('Not Working')

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
                # If checkbox is not marked
            else:
                Messagebox.show_error(
                    "Please check the checkbox", title="No checkbox error", alert=True
                )
                return

    """
    Functions from here down
    """

    # This is used to open the directory selection dialog and passes the filepath to the next function
    def open_file_dialog(self):
        directory_path = filedialog.askdirectory(title="Select a Directory")
        if directory_path:
            self.key_filepath = directory_path

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
    Decryption defs
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
            print('select a file')
    # Calls the decrypt function outside of init
    def start_decrypt(self, file_name, key_dir):
        if file_name and key_dir:
            try:
                encryptor.decrypt_file(file_name, key_dir)
                self.decrypt_file_selected.config(text="No file selected")
            except TypeError as e:
                print(f"error occured{e}")


root = tk.Window(iconphoto="CS404.png", themename="darkly")  # This is the main window
locker_404(root)  # This calls the window with the set parameters to the specific window
root.mainloop()  # Runs the main loop function on the window allowing it to work.
