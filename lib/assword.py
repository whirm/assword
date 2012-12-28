import os
import io
import gpgme
import json

class DatabaseSignatureError():
    def __init__(self, sigs):
        self.sigs = sigs

class Database():
    """An Assword database."""

    def __init__(self, path, key):
        self.path = path
        # key for signer and recipient
        # FIXME: should these be separated?
        self.key = key

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

    def _encryptDB(self, data):
        recipient = self.gpg.get_key(self.key)
        signer = self.gpg.get_key(self.key)
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

    def add(self, context=None, info=None, password=None, secrets=None):
        """Add a new entry to the database."""
        newindex = self._newindex()
        self.entries[newindex] = {}
        self.entries[newindex]['context'] = context
        self.entries[newindex]['info'] = info
        self.entries[newindex]['password'] = password
        self.entries[newindex]['secrets'] = secrets
        return newindex

    def save(self):
        """Save a modified database.  This needs to be done after add() to save changes."""
        cleardata = io.BytesIO(json.dumps(self.entries, sort_keys=True, indent=2))
        encdata = self._encryptDB(cleardata)
        if os.path.exists(self.path):
            os.rename(self.path, self.path + '.bak')
        with open(self.path, 'w') as f:
            f.write(encdata.getvalue())

    def search(self, query=None):
        """Search the database entry 'context' and 'info' fields for string."""
        query = ' '.join(query)
        mset = {}
        for index, entry in self.entries.iteritems():
            if query:
                if entry['context'] and query in entry['context']:
                    mset[index] = entry
                    continue
                if entry['info'] and query in entry['info']:
                    mset[index] = entry
                    continue
            else:
                mset[index] = entry
        return mset
