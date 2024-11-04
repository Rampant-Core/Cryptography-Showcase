def caesar_cipher(text, shift):
    encrypted_text = ""

    for char in text:
        # Check if character is an uppercase letter
        if char.isupper():
            encrypted_text += chr((ord(char) + shift - 65) % 26 + 65)
        # Check if character is a lowercase letter
        elif char.islower():
            encrypted_text += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            # If it's neither, just add the character as is (like punctuation or spaces)
            encrypted_text += char

    return encrypted_text


# Example usage:
text = "Hello, World!"
shift = 7
print("Original Text:", text)
print("Encrypted Text:", caesar_cipher(text, shift))
