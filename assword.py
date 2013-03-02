import os
import io
import gpgme
import json
import time
import Tkinter

class DatabaseKeyError(Exception):
    """Indicates GPG key error."""
    def __init__(self, msg):
        self.msg = 'Assword key error: %s' % (msg)
    def __str__(self):
        return repr(self.msg)

class DatabasePathError(Exception):
    """Indicates path error."""
    def __init__(self, msg, path):
        self.msg = 'Assword database error: %s: %s' % (msg, path)
    def __str__(self):
        return repr(self.msg)

class DatabaseSignatureError(Exception):
    """Indicates signatures on database file were not fully valid."""
    def __init__(self, sigs, msg):
        self.sigs = sigs
        self.msg = 'Assword signature error: %s' % (msg)
    def __str__(self):
        return repr(self.msg)

class Database():
    """An Assword database."""

    def __init__(self, dbpath=None, keyid=None):
        """Database at dbpath will be decrypted and loaded into memory.
If dbpath not specified, empty database will be initialized."""
        self.dbpath = dbpath
        self.keyid = keyid

        self.gpg = gpgme.Context()
        self.gpg.armor = True

        if self.dbpath and os.path.exists(self.dbpath):
            cleardata = self._decryptDB(self.dbpath)
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
            raise DatabaseSignatureError(sigs, 'Signature on database was not fully valid.')
        data.seek(0)
        return data

    def _encryptDB(self, data, keyid):
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
        # Return a potential new entry index.
        indicies = [int(index) for index in self.entries.keys()]
        if not indicies: indicies = [-1]
        return str(max(indicies) + 1)

    def add(self, context, password):
        """Add a new entry to the database.
Database won't be saved to disk until save()."""
        newindex = self._newindex()
        self.entries[newindex] = {}
        self.entries[newindex]['context'] = context
        self.entries[newindex]['password'] = password
        self.entries[newindex]['date'] = int(time.time())
        return newindex

    def remove(self, index):
        """Remove an entry from the database.
Database won't be saved to disk until save()."""
        del self.entries[index]

    def save(self, keyid=None, path=None):
        """Save database to disk.
Key ID must either be specified here or at database initialization.
If path not specified, database will be saved at original dbpath location."""
        if not keyid:
            keyid = self.keyid
        if not keyid:
            raise DatabaseKeyError('Key ID for decryption not specified.')
        if not path:
            path = self.dbpath
        if not path:
            raise DatabasePathError('Save path not specified.')
        cleardata = io.BytesIO(json.dumps(self.entries, sort_keys=True, indent=2))
        encdata = self._encryptDB(cleardata, keyid)
        newpath = path + '.new'
        bakpath = path + '.bak'
        with open(newpath, 'w') as f:
            f.write(encdata.getvalue())
        if os.path.exists(path):
            os.rename(path, bakpath)
        os.rename(newpath, path)

    def search(self, query=None):
        """Search the 'context' fields of database entries for string.
If query is None, all entries will be returned.  Special query
'id:<id>' will return single entry."""
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

############################################################

class Xsearch():
    """Assword X-based query UI."""
    # Lifted largely from: http://code.activestate.com/recipes/410646-tkinter-listbox-example/

    def __init__(self, dbpath, query=None):
        """Entire action of this class is in initialization.
May specify initial query with 'query'."""
        self.dbpath = dbpath
        self.query = None
        self.db = None
        self.results = None
        self.selected = None

        if not os.path.exists(self.dbpath):
            self._winInit()
            self._errorMessage("""Password database does not exist.
Add passwords to the database from the command line with 'assword add'.
See 'assword help' for more information.""")
            return

        if query:
            # If we have an intial query, directly do a search without
            # initializing any X objects.  This will initialize the
            # database and potentially return entries.
            self._search(query)
            # If only a single entry is found, _search() will set the
            # result and attempt to close any X objects (of which
            # there are none).  Since we don't need to initialize any
            # GUI, return the initialization immediately.
            # See .returnValue().
            if len(self.results) == 1:
                self._selectAndReturn(self.results.keys()[0])
                return

        self._winInit()
        self._promptDisplay()
        self._selectInit()
        if self.query:
            self._query()

    def _dbInit(self):
        if not self.db:
            self.db = Database(self.dbpath)

    def _search(self, query):
        self.query = query
        if query == '':
            self.results = None
            return
        self._dbInit()
        self.results = self.db.search(self.query)

    def _winInit(self):
        self.master = Tkinter.Tk(className='assword')
        self.master.title("assword")
        self.main = Tkinter.Frame(self.master)
        self.main.pack(ipadx=5, ipady=5)

    def _errorMessage(self, text):
        Tkinter.Label(self.main, text=text).pack(padx=5, pady=5)
        button = Tkinter.Button(self.main, text="OK", command=self._cancel)
        button.pack()
        button.bind("<Return>", self._cancel)
        button.bind("<Escape>", self._cancel)
        button.focus_set()

    def _promptDisplay(self):
        self.prompt = Tkinter.Frame(self.master)
        self.promptLabel = Tkinter.Label(self.prompt, text="Password search:")
        self.promptLabel.pack(pady=2)
        self.promptEntry = Tkinter.Entry(self.prompt)
        if self.query:
            self.promptEntry.insert(0, self.query)
        self.promptEntry.pack()
        self.promptEntry.bind("<Return>", self._query)
        self.promptEntry.bind("<Escape>", self._cancel)
        self.prompt.pack(padx=5, pady=5, ipadx=2, ipady=2)
        self.promptEntry.focus_set()

    def _selectInit(self):
        self.select = Tkinter.Frame(self.master)
        self.selectLabel = Tkinter.Label(self.select)
        self.selectLabel.pack(pady=2)
        self.selectList = Tkinter.Listbox(self.select, selectmode=Tkinter.SINGLE)
        self.selectList.bind("<Return>", self._choose)
        self.selectList.bind("<Escape>", self._cancel)

    def _selectDisplay(self):
        # clear the listbox
        self.selectList.delete(0, Tkinter.END)
        self.select.pack(padx=5, pady=5, ipadx=2, ipady=2)
        if not self.results or len(self.results) == 0:
            self.selectLabel.config(text="No results found.")
            self.selectList.pack_forget()
            self.promptEntry.focus_set()
            return
        self.selectLabel.config(text="Select context:")
        listwidth = 0
        listheight = 0
        # we need a list to store indices of entries in selector
        self.indices = []
        for index, entry in sorted(self.results.iteritems()):
            self.indices.append(index)
            text = "%s" % (entry['context'])
            listwidth = max(listwidth, len(text))
            listheight += 1
            self.selectList.insert(Tkinter.END, text)
        self.selectList.config(
            width=listwidth,
            height=listheight,
            )
        self.selectList.pack()
        self.selectList.focus_set()

    ##########
    # These are meant to be bound to key events:

    def _query(self, event=None):
        self._search(self.promptEntry.get())
        self._selectDisplay()

    def _choose(self, event=None):
        item = self.selectList.index(Tkinter.ACTIVE)
        self._selectAndReturn(self.indices[item])

    def _cancel(self, event=None):
        self._die()

    ##########

    def _selectAndReturn(self, index):
        self.selected = self.results[str(index)]
        self._die()

    def _die(self):
        if 'main' in dir(self):
            self.main.destroy()

    def returnValue(self):
        """Return user-selected search result of database query."""
        if 'master' in dir(self):
            self.master.wait_window(self.main)
        return self.selected
