import pickle
import os
import json
import hashlib
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitive.ciphers.aead import AESGCM
from cryptography.exceptions import  InvalidTag


class PrivNotes:
  MAX_NOTE_LEN = 2048;

  @staticmethod
  def _mac(key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()

  def _tag(self, title):
    return self._mac(self._tk, bytes(title, 'ascii'))

  def _keys(self, password, salt):
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 2_000_000)
    source = kdf.derive(bytes(password, 'ascii'))
    self._tk = self._mac(source, b'title')
    self._ek = self._mac(source, b'encryption')
    self._vk = self._mac(source, b'verification')

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

    try:

      if data is None:
        self._salt = os.urandom(16)
        self._keys(password, self._salt)
        self.kvs = {}
        return
      
      raw = bytes.fromhex(data)

      if checksum is not None and hashlib.sha256(raw).hexdigest() != checksum:
        raise ValueError('Checksum mismatch')
      
      obj = json.loads(raw.decode('ascii'))

      # if obj.get('v') != 1:
      #   raise ValueError('Malformed data')
      self._salt = bytes.fromhex(obj['s'])
      if len(self._salt) != 16:
        raise ValueError('Malformed data')
      
      self._keys(password, self._salt)
      verifier = bytes.fromhex(obj['vfy'])

      if len(verifier) < 28:
        raise ValueError('Malformed data')
      
      checked = AESGCM(self._vk).decrypt(verifier[:12], verifier[12:], b'private-notes-verifier-v1')

      if checked != b'private-notes-verifier-v1':
        raise ValueError('Incorrect password')
      
      entries = obj['entries']

      if not isinstance(entries, list):
        raise ValueError('Malformed data')
      
      self.kvs = {}

      for entry in entries:
        if not isinstance(entry, list) or len(entry) != 2:
          raise ValueError('Malformed data')
        tag = bytes.fromhex(entry[0])
        record = bytes.fromhex(entry[1])

        if len(tag) != 32 or len(record) != 8 + self.MAX_NOTE_LEN + 2 + 16:
          raise ValueError('Malformed data')
        if tag in self.kvs:
          raise ValueError('Malformed data')

        count = record[:8]
        nonce = self._mac(self._ek, b'nonce' + tag + count)[:12]
        plaintext = AESGCM(self._ek).decrypt(nonce, record[8:], b'private-notes-record-v1' + tag + count)
        length = int.from_bytes(plaintext[:2], 'big')

        if (len(plaintext) != self.MAX_NOTE_LEN + 2 or length > self.MAX_NOTE_LEN or plaintext[2 + length:] != bytes(self.MAX_NOTE_LEN - length)):
          raise ValueError('Malformed data')
        
        self.kvs[tag] = record
      
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError, UnicodeEncodeError, OverflowError, json.JSONDecodeError, InvalidTag):
      raise ValueError('Invalid data')
    
    return

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    return pickle.dumps(self.kvs).hex(), ''

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    if title in self.kvs:
      return self.kvs[title]
    return None

  def set(self, title, note):
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
    
    self.kvs[title] = note


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    if title in self.kvs:
      del self.kvs[title]
      return True

    return False
