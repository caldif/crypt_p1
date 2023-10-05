import pickle, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class PrivNotes:
  MAX_NOTE_LEN = 2048
  NONCE_COUNTER = 2**64 #8 bytes hehe

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    self.kvs= {}
    if data is not None:
      #going to have to slice data? depends on how structure dump
      data_tuple = pickle.loads(bytes.fromhex(data))
      self.salt, self.signature, self.kvs = data_tuple
      print(self.salt)
      print(self.signature)
      print(self.kvs)
    else:

      self.salt = os.urandom(16)
      kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt,iterations = 2000000, backend = default_backend())
      self.key = kdf.derive(bytes(password, "ascii"))
      h = hmac.HMAC(self.key, hashes.SHA256())
      h.update(bytes("Jessica is cool", "ascii"))
      self.signature = h.finalize()

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)

    """
    #data is going to have to be signature||kvs
    #might have to pad sig to standard length?
    return pickle.dumps(self.kvs).hex(), ''

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    #Key derivation for passed title encryption
    passed_title_hmac = hmac.HMAC(self.key, hashes.SHA256())
    passed_title_hmac.update(bytes("Title Hash", "ascii"))
    check_title = passed_title_hmac.finalize()

    #New Title encryption
    h = hmac.HMAC(check_title, hashes.SHA256())
    h.update(bytes(title, "ascii"))
    e_passed_title = h.finalize()

    if e_passed_title in self.kvs:
      enc_text = self.kvs[e_passed_title]
      e_note , note_nonce, e_length, length_nonce = enc_text

      #Length Key Gen and Encryption
      length_hmac = hmac.HMAC(self.key, hashes.SHA256())
      length_hmac.update(bytes("Length hash", "ascii"))
      old_key_length = length_hmac.finalize()

      #length decryption
      l = AESGCM(old_key_length)
      d_length = l.decrypt(nonce=bytes(str(length_nonce), "ascii"), data=e_length, associated_data=None)

      #Note Key Gen and Encryption
      note_hmac = hmac.HMAC(self.key, hashes.SHA256())
      note_hmac.update(bytes("Note AES Hash", "ascii"))
      old_note_key = note_hmac.finalize()

      #note decryption
      n = AESGCM(old_note_key)
      d_note = n.decrypt(nonce=bytes(str(note_nonce), "ascii"), data=e_note, associated_data=bytes(title, "ascii"))

      #return note
      return str(d_note[:int(d_length)], encoding='utf-8')
    
    #returns none if title is not in kvs
    return None

  def set(self, title:str, note: str):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """

    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')
    
    #Key derivation for title encryption
    title_hmac = hmac.HMAC(self.key, hashes.SHA256())
    title_hmac.update(bytes("Title Hash", "ascii"))
    new_key_title = title_hmac.finalize()

    #Title encryption
    h = hmac.HMAC(new_key_title, hashes.SHA256())
    h.update(bytes(title, "ascii"))
    e_title = h.finalize()

    #Length Key Gen and Encryption
    length_hmac = hmac.HMAC(self.key, hashes.SHA256())
    length_hmac.update(bytes("Length hash", "ascii"))
    new_key_length = length_hmac.finalize()

    # l = hmac.HMAC(new_key_length, hashes.SHA256())
    # l.update(bytes(str(len(note)), "ascii"))
    # e_length = l.finalize()
    #append nonce to the end 
    l = AESGCM(new_key_length)
    padded_length = str(len(note)).rjust(4, "0")
    e_length = l.encrypt(nonce=bytes(str(self.NONCE_COUNTER), "ascii"), data=bytes(padded_length, "ascii"), associated_data=None) 
    e_length = e_length
    length_nonce = self.NONCE_COUNTER
    self.NONCE_COUNTER += 1
    

    #Padding (converting 2048 bytes to bits)
    padded_note = note.ljust((self.MAX_NOTE_LEN)*8, "0")
    
    
    #Key derivation for note encryption
    note_hmac = hmac.HMAC(self.key, hashes.SHA256())
    note_hmac.update(bytes("Note AES Hash", "ascii"))
    new_key_note = note_hmac.finalize()

    #Note encryption
    a = AESGCM(new_key_note)
    e_note = a.encrypt(nonce=bytes(str(self.NONCE_COUNTER), "ascii"), data=bytes(padded_note, "ascii"), associated_data=bytes(title, "ascii")) #can we put in the title 
    note_nonce = self.NONCE_COUNTER
    self.NONCE_COUNTER += 1

    #Storage of encrypted note and key 
    self.kvs[e_title] = (e_note, note_nonce, e_length, length_nonce)#is it possible that this reveals info about the length of the length YES SO I FIXED IT??







  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    #Key derivation for passed title encryption
    passed_title_hmac = hmac.HMAC(self.key, hashes.SHA256())
    passed_title_hmac.update(bytes("Title Hash", "ascii"))
    check_title = passed_title_hmac.finalize()

    #Title encryption
    h = hmac.HMAC(check_title, hashes.SHA256())
    h.update(bytes(title, "ascii"))
    e_passed_title = h.finalize()

    if e_passed_title in self.kvs:
      del self.kvs[e_passed_title]
      return True

    return False
