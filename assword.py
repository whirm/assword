import os
import io
import gpgme
import json
import time

class DatabaseKeyError(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return repr(self.msg)

class DatabaseSignatureError():
    def __init__(self, sigs):
        self.sigs = sigs

class Database():
    """An Assword database."""

    def __init__(self, path, keyid=None):
        self.path = path
        self.keyid = keyid

        self.gpg = gpgme.Context()
        self.gpg.armor = True

        if os.path.exists(self.path):
            cleardata = self._decryptDB(self.path)
            self.entries = json.loads(cleardata.getvalue())
        else:
            self.entries = {}

    def _decryptDB(self, path):
        data = io.BytesIO()
        with io.BytesIO() as encdata:
            with open(path, 'rb') as f:
                encdata.write(f.read())
                encdata.seek(0)
                sigs = self.gpg.decrypt_verify(encdata, data)
        # check signature
        if not sigs[0].validity >= gpgme.VALIDITY_FULL:
            raise DatabaseSignatureError(sigs)
        data.seek(0)
        return data

    def _encryptDB(self, data, keyid=None):
        if not keyid:
            keyid = self.keyid
        if not keyid:
            raise DatabaseKeyError('Key ID for decryption not specified.')
        # The signer and the recipient are assumed to be the same.
        # FIXME: should these be separated?
        try:
            recipient = self.gpg.get_key(keyid or self.keyid)
            signer = self.gpg.get_key(keyid)
        except:
            raise DatabaseKeyError('GPG could not retrieve encryption key.')
        self.gpg.signers = [signer]
        encdata = io.BytesIO()
        data.seek(0)
        sigs = self.gpg.encrypt_sign([recipient],
                                     gpgme.ENCRYPT_ALWAYS_TRUST,
                                     data,
                                     encdata)
        encdata.seek(0)
        return encdata

    def _newindex(self):
        indicies = [int(index) for index in self.entries.keys()]
        if not indicies: indicies = [-1]
        return str(max(indicies) + 1)

    def add(self, context, password):
        """Add a new entry to the database."""
        newindex = self._newindex()
        self.entries[newindex] = {}
        self.entries[newindex]['context'] = context
        self.entries[newindex]['password'] = password
        self.entries[newindex]['date'] = int(time.time())
        return newindex

    def save(self, keyid=None):
        """Save a modified database.  This needs to be done after add() to save changes."""
        cleardata = io.BytesIO(json.dumps(self.entries, sort_keys=True, indent=2))
        encdata = self._encryptDB(cleardata, keyid)
        if os.path.exists(self.path):
            os.rename(self.path, self.path + '.bak')
        with open(self.path, 'w') as f:
            f.write(encdata.getvalue())

    def search(self, query=None):
        """Search the database entry 'context' and 'info' fields for string."""
        # look for special search string for single id
        if query.find('id:') == 0:
            index = query[3:]
            if index in self.entries:
                return {index: self.entries[index]}
        mset = {}
        for index, entry in self.entries.iteritems():
            if query:
                if entry['context'] and query in entry['context']:
                    mset[index] = entry
                    continue
            else:
                mset[index] = entry
        return mset
