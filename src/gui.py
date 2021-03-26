from tkinter import *
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from time import time
from rsa import *
import string

class Gui:
	def __init__(self):
		self.window = Tk()
		self.window.title("Tugas Kecil 3 II4031 - 13517055 13517139")
		self.window.geometry('670x640')
		self.window.resizable(False, False)

		self.rsa = RSA()

		self.key_length = [ 16, 64, 256, 1024 ]

		self.label_choose_key_length = Label(self.window, text='Key Length (bit) ')
		self.label_choose_key_length.grid(column=0, row=3, pady=10, padx=10, sticky=SW)

		self.combobox_key_length = ttk.Combobox(self.window, values=self.key_length, width=10, state="readonly")
		self.combobox_key_length.grid(column=1, row=3, pady=10, sticky=SW)
		self.combobox_key_length.current(0)
		self.combobox_key_length.bind('<<ComboboxSelected>>', self.handler)

		self.btn_generate_key = Button(self.window, text="Generate Keys", width=15, command=self.generate_key_clicked)
		self.btn_generate_key.grid(column=2, row=3, sticky='E', padx=20)

		self.label_public_key = Label(self.window, text='Public Key ')
		self.label_public_key.grid(column=0, row=4, sticky=W, padx=10)

		self.public_key = Entry(self.window, width=40)
		self.public_key.grid(column=1, row=4, sticky=W)

		self.btn_open_public_key = Button(self.window, text="Open Public Key", width=15, command=self.open_pub_key_clicked)
		self.btn_open_public_key.grid(column=2, row=4, sticky='E', padx=20)

		self.label_private_key = Label(self.window, text='Private Key')
		self.label_private_key.grid(column=0, row=5, sticky=W, padx=10)

		self.private_key = Entry(self.window, width=40)
		self.private_key.grid(column=1, row=5, sticky=W)

		self.btn_open_private_key = Button(self.window, text="Open Private Key", width=15, command=self.open_pri_key_clicked)
		self.btn_open_private_key.grid(column=2, row=5, sticky='E', padx=20)
		
		self.btn_save_keys = Button(self.window, text="Save Keys", width=15, command=self.save_keys_clicked)
		self.btn_save_keys.grid(column=0, row=6, sticky=E, pady=5, padx=10)

		self.plaintext = []
		self.btn_openfile_plaintext = Button(self.window, text="Open File Plaintext", width=15, command=self.choose_plaintext_file)
		self.btn_openfile_plaintext.grid(column=0, row=7, sticky=E, pady=5, padx=10)

		self.ciphertext = []
		self.btn_openfile_ciphertext = Button(self.window, text="Open File Ciphertext", width=15, command=self.choose_ciphertext_file)
		self.btn_openfile_ciphertext.grid(column=0, row=8, sticky=E, pady=5, padx=10)

		self.label_plaintext_path = Label(self.window, text="")
		self.label_plaintext_path.grid(column=1, row=7, columnspan=3, sticky=W, padx=10)

		self.label_ciphertext_path = Label(self.window, text="")
		self.label_ciphertext_path.grid(column=1, row=8, columnspan=3, sticky=W, padx=10)

		self.is_encrypt = True

		self.btn_encryptdecrypt = Button(self.window, text="Encrypt", width=15, command=self.encryptdecrypt_clicked)
		self.btn_encryptdecrypt.grid(column=2, row=10, sticky='E', padx=20)

		self.label_ciphertext = Label(self.window, text="Ciphertext")
		self.label_ciphertext.grid(column=0, row=11, sticky=W, padx=10, pady=(20, 5))

		self.textarea = scrolledtext.ScrolledText(self.window, width=70, height=15)
		self.textarea.grid(column=0, row=12, columnspan=3, padx=5)
	
		self.label_file = Label(self.window, text="Ciphertext File: ")
		self.label_file.grid(column=0, row=13, sticky=W, padx=10, pady=(20, 5))

		self.label_filepath = Label(self.window, text='')
		self.label_filepath.grid(column=1, row=13, sticky=W, padx=10, pady=(20, 5))

		self.label_time_execution = Label(self.window, text='')
		self.label_time_execution.grid(column=1, row=14, sticky=W, padx=10)

		self.label_filesize = Label(self.window, text='')
		self.label_filesize.grid(column=2, row=14, sticky=W, padx=10)

	def generate_key_clicked(self):
		length = self.key_length[self.combobox_key_length.current()]
		self.rsa.generate_key_pairs(int(length))
		self.public_key.delete("1", END)
		self.public_key.insert("1", self.rsa.public_key)
		self.private_key.delete("1", END)
		self.private_key.insert("1", self.rsa.private_key)

	def open_pub_key_clicked(self):
		filename = filedialog.askopenfilename()
		if filename != '' and type(filename) == str:
			with open(filename, "r") as file:
				self.public_key.delete("1", END)
				self.public_key.insert("1", file.read())

	def open_pri_key_clicked(self):
		filename = filedialog.askopenfilename()
		if filename != '' and type(filename) == str:
			with open(filename, "r") as file:
				self.private_key.delete("1", END)
				self.private_key.insert("1", file.read())

	def save_keys_clicked(self):
		filename = filedialog.asksaveasfilename()
		if filename != '' and type(filename) == str:
			with open(filename+".pub", "wb") as file:
				content = self.public_key.get()
				file.write(bytes(content.encode()))
			with open(filename+".pri", "wb") as file:
				content = self.private_key.get()
				file.write(bytes(content.encode()))	
	
	def choose_plaintext_file(self) :
		filename = filedialog.askopenfilename()
		if filename != '' and type(filename) == str:
			with open(filename, "rb") as file:
				self.plaintext = file.read()
				self.ciphertext = []
				self.label_ciphertext.config(text="Plaintext")
				self.textarea.delete("1.0", END)
				self.textarea.insert("1.0", self.plaintext)
				self.label_plaintext_path.config(text=filename)
				self.label_ciphertext_path.config(text="")
				self.btn_encryptdecrypt.config(text="Encrypt")
				self.is_encrypt = True
	
	def choose_ciphertext_file(self) :
		filename = filedialog.askopenfilename()
		if filename != '' and type(filename) == str:
			with open(filename, "r") as file:
				self.ciphertext = file.read()
				self.plaintext = []
				self.label_ciphertext.config(text="Ciphertext")
				self.textarea.delete("1.0", END)
				self.textarea.insert("1.0", self.ciphertext)
				self.label_ciphertext_path.config(text=filename)
				self.label_plaintext_path.config(text="")
				self.btn_encryptdecrypt.config(text="Decrypt")
				self.is_encrypt = False

	def handler(self, event):
		current = self.combobox_key_length.current()

	def encryptdecrypt_clicked(self):
		if self.rsa.public_key == (0,0):
			self.rsa.public_key = tuple([int(x) for x in self.public_key.get().split()])
		if self.rsa.private_key == (0,0):
			self.rsa.private_key = tuple([int(x) for x in self.private_key.get().split()])
		if self.is_encrypt:
			self.label_file.config(text="Ciphertext File:")
			try:
				start = time()
				self.ciphertext = self.rsa.encrypt(self.plaintext)
				end = time()
				self.label_time_execution.config(text="time: "+str(end-start)+" second")
				self.label_ciphertext.config(text="Ciphertext")
				self.textarea.delete("1.0", END)
				self.textarea.insert("1.0", self.ciphertext)
			except Exception as e:
				messagebox.showerror("Error", e)
			
			self.save_file(self.ciphertext)			
		else:
			self.label_file.config(text="Plaintext File:")
			try:
				start = time()
				self.plaintext = self.rsa.decrypt(self.ciphertext)
				end = time()
				self.label_time_execution.config(text="time: "+str(end-start)+" second")
				self.label_ciphertext.config(text="Plaintext")
				self.textarea.delete("1.0", END)
				self.textarea.insert("1.0", self.plaintext)
			except Exception as e:
				messagebox.showerror("Error", e)
			
			self.save_file(self.plaintext)
	
	def save_file(self, content) :
		filename = filedialog.asksaveasfilename()
		if filename != '' and type(filename) == str:
			with open(filename, "wb") as file:
				file.write(bytes(content.encode()))
				file.seek(0,2)
				self.label_filesize.config(text=str(file.tell())+" B")
				self.label_filepath.config(text=filename)


if __name__ == "__main__":
   gui = Gui()
   gui.window.mainloop()