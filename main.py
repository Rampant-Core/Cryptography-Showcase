import ttkbootstrap as tk
from tkinter import filedialog
from ttkbootstrap.dialogs import Messagebox
import locker
from PIL import Image, ImageTk

encryptor = locker.Cs404_locker()  # Calls an instance of the 404 locker class


class locker_404:
    def __init__(
        self, root
    ):  # Here are the parameters for the window contained in a class
        root.title("404 Cryptography Demo")
        root.geometry("800x400")
        root.maxsize(800, 400)
        self.checkbox_var = tk.BooleanVar()
        self.key_filepath = None
        self.decrypt_key_filepath = None
        self.key_name = None
        self.iconphoto = ""
        self.file_to_encrypt = None
        self.selected_key_label = None

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
        ).grid(column=0, row=0, padx=30, pady=30, sticky="nsew")
        # Tab 1 Frame
        tab_frame_1 = tk.Frame(tab1, width=60, height=90, borderwidth=2)
        tab_frame_1.grid(row=0, column=0)
        # Tab 1 text frame
        text_frame_1 = tk.Text(
            tab_frame_1, wrap="word", width=60, height=60, font="Helvetica, 18"
        )
        text_frame_1.grid(row=0, column=1)
        # Tab 1 Text fram contents
        tab_info_1 = "This is an application created to show how encryption works on files in a system. Created only for educational purposes for the CS404 Club.Be aware improper use of this tool may lead to data loss or worse, use at your own risk on files that are important. This should not be used to keep files safe."
        text_frame_1.insert("1.0", tab_info_1)
        text_frame_1.config(state="disabled")
        # Image Display
        image = Image.open("CS404.png")
        image = image.resize((159, 211), Image.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        image_label = tk.Label(tab_frame_1, image=photo)
        image_label.grid(row=0, column=0, sticky="nsew")
        image_label.image = photo
        """
        Key generation tab
        """
        # Label for tab 2 desc
        tk.Label(
            tab2,
            text="Select a folder to generate a key and set the name you would like",
        ).grid(column=0, row=0, padx=30, pady=30)
        key_creation = tk.Button(
            tab2, text="Generate a Key", command=self.make_key, style="danger"
        )
        key_creation.grid(column=1, row=0)
        # Button for selecting filepath
        open_button = tk.Button(
            tab2,
            text="Select Folder for Key",
            command=self.open_file_dialog,
            style="danger",
        )
        open_button.grid(column=2, row=0)
        # Entry for Filename
        self.filename_entry = tk.Entry(tab2, style="danger")
        self.filename_entry.grid(column=1, row=1)
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

        # Checkbox state remove after def is created
        def show_state():
            self.checkbox_var.get()

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
            command=show_state,
        )
        checkbox.grid(column=2, row=4, padx=10, pady=10, sticky="nsew")

        # Button for starting encryption
        call_encrypt = tk.Button(
            encryption_frame, text="Encrypt", command=None, style="danger"
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
        # Tab 1 Text fram contents
        tab_info_3 = "This uses a 32 bit AES-128 key created by the previous tab to convert a file into cyphertext making it unreadable, any file this program encrypts has their extension automatically changed to .404 Not recommended to be used on important files, this is just a demonstration of how symmetric key encryption works. Use on important data at your own risk."
        text_frame_3.insert("1.0", tab_info_3)
        text_frame_3.config(state="disabled")

    # def for button to make an encryption key
    # Needs two parameters for input, a filepath to place the key and a name for the key
    def make_key(self):
        self.key_name = self.filename_entry.get()
        if self.key_filepath and self.key_name is None:
            Messagebox.show_error(
                "Please select a folder and enter a name for the key",
                title="Error no folder & name",
            )
            return
        if self.key_name is None or self.key_name == "":
            Messagebox.show_error(
                "Please enter a name for the key", title="No name Error"
            )
            return
        if self.key_filepath is None:
            Messagebox.show_error(
                "Please select a folder to save the key in", title="No folder Error"
            )
            return
        if self.key_filepath and self.key_name is not None:
            encryptor.generate_key(self.key_filepath, self.key_name)
            Messagebox.show_info(
                f"A key {self.key_name} Has been created at {self.key_filepath}.404key",
                title="Key Creation successful",
            )

    """
    Functions from here down
    """

    # This is used to open the directory selection dialog and passes the filepath to the next function
    def open_file_dialog(self):
        directory_path = filedialog.askdirectory(title="Select a Directory")
        if directory_path:
            self.key_filepath = directory_path

    # This will be used to load a key in for encryption/decryption
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


root = tk.Window(iconphoto="CS404.png", themename="darkly")  # This is the main window
locker_404(root)  # This calls the window with the set parameters to the specific window
root.mainloop()  # Runs the main loop function on the window allowing it to work.
