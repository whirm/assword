import os
import io
import gpgme
import json
import time
import base64
import datetime
import Tkinter

############################################################

DEFAULT_NEW_PASSWORD_OCTETS=18

def pwgen(bytes):
    s = os.urandom(bytes)
    return base64.b64encode(s)

############################################################

class DatabaseError(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return repr(self.msg)

class Database():
    """An Assword database."""

    def __init__(self, dbpath=None, keyid=None):
        """Database at dbpath will be decrypted and loaded into memory.
If dbpath not specified, empty database will be initialized."""
        self.dbpath = dbpath
        self.keyid = keyid

        # default database information
        self.type = 'assword'
        self.version = 1
        self.entries = {}

        self.gpg = gpgme.Context()
        self.gpg.armor = True

        if self.dbpath and os.path.exists(self.dbpath):
            try:
                cleardata = self._decryptDB(self.dbpath)
                # FIXME: trap exception if json corrupt
                jsondata = json.loads(cleardata.getvalue())
            except IOError as e:
                raise DatabaseError(e)
            except gpgme.GpgmeError as e:
                raise DatabaseError('Decryption error: %s' % (e[2]))

            # unpack the json data
            if 'type' not in jsondata or jsondata['type'] != self.type:
                raise DatabaseError('Database is not a proper assword database.')
            if 'version' not in jsondata or jsondata['version'] != self.version:
                raise DatabaseError('Incompatible database.')
            self.entries = jsondata['entries']

    def _decryptDB(self, path):
        data = io.BytesIO()
        with io.BytesIO() as encdata:
            with open(path, 'rb') as f:
                encdata.write(f.read())
                encdata.seek(0)
                sigs = self.gpg.decrypt_verify(encdata, data)
        # check signature
        if not sigs[0].validity >= gpgme.VALIDITY_FULL:
            raise DatabaseError(sigs, 'Signature on database was not fully valid.')
        data.seek(0)
        return data

    def _encryptDB(self, data, keyid):
        # The signer and the recipient are assumed to be the same.
        # FIXME: should these be separated?
        try:
            recipient = self.gpg.get_key(keyid or self.keyid)
            signer = self.gpg.get_key(keyid)
        except:
            raise DatabaseError('Could not retrieve GPG encryption key.')
        self.gpg.signers = [signer]
        encdata = io.BytesIO()
        data.seek(0)
        sigs = self.gpg.encrypt_sign([recipient],
                                     gpgme.ENCRYPT_ALWAYS_TRUST,
                                     data,
                                     encdata)
        encdata.seek(0)
        return encdata

    def add(self, context, password=None):
        """Add a new entry to the database.
Database won't be saved to disk until save()."""
        if not password:
            bytes = int(os.getenv('ASSWORD_PASSWORD', DEFAULT_NEW_PASSWORD_OCTETS))
            print "bytes: %d"%(bytes)
            password = pwgen(bytes)

        e = {'password': password,
             'date': datetime.datetime.now().isoformat()}
        self.entries[context] = e
        return e

    def remove(self, context):
        """Remove an entry from the database.
Database won't be saved to disk until save()."""
        del self.entries[context]

    def save(self, keyid=None, path=None):
        """Save database to disk.
Key ID must either be specified here or at database initialization.
If path not specified, database will be saved at original dbpath location."""
        # FIXME: should check that recipient is not different than who
        # the db was originally encrypted for
        if not keyid:
            keyid = self.keyid
        if not keyid:
            raise DatabaseError('Key ID for decryption not specified.')
        if not path:
            path = self.dbpath
        if not path:
            raise DatabaseError('Save path not specified.')
        jsondata = {'type': self.type,
                    'version': self.version,
                    'entries': self.entries}
        cleardata = io.BytesIO(json.dumps(jsondata, indent=2))
        encdata = self._encryptDB(cleardata, keyid)
        newpath = path + '.new'
        bakpath = path + '.bak'
        with open(newpath, 'w') as f:
            f.write(encdata.getvalue())
        if os.path.exists(path):
            os.rename(path, bakpath)
        os.rename(newpath, path)

    def search(self, query=None):
        """Search for query in contexts.
If query is None, all entries will be returned."""
        mset = {}
        for context, entry in self.entries.iteritems():
            # simple substring match
            if query in context:
                mset[context] = entry
        return mset

    def __getitem__(self, context):
        '''Return database entry for exact context'''
        return self.entries[context]

############################################################

class Xsearch():
    """Assword X-based query UI."""
    # Lifted largely from: http://code.activestate.com/recipes/410646-tkinter-listbox-example/

    def __init__(self, dbpath, query=None, keyid=None):
        """Entire action of this class is in initialization.
May specify initial query with 'query'."""
        self.dbpath = dbpath
        self.query = None
        self.keyid = keyid
        self.db = None
        self.results = None
        self.selected = None
        self.master = None
        self.main = None

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

    def _centerWindow(self):
        self.master.update_idletasks()
        sw = self.master.winfo_screenwidth()
        sh = self.master.winfo_screenheight()
        w, h = tuple(int(_) for _ in self.master.geometry().split('+')[0].split('x'))
        x = (sw - w)/2
        y = (sh - h)/2
        geometry = '%dx%d+%d+%d' % (w, h, x, y)
        self.master.geometry(geometry)

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
        self.selectButton = Tkinter.Button(self.select)
        self.selectButton.bind("<Escape>", self._cancel)

    def _selectDisplay(self):
        # clear the listbox
        self.selectList.delete(0, Tkinter.END)
        self.select.pack(padx=5, pady=5, ipadx=2, ipady=2)
        self.selectButton.pack_forget()

        # allow user to create entry if no results
        if not self.results or len(self.results) == 0:
            self.selectLabel.config(text="""No results found.

Create entry with above string as context:""")
            self.selectList.pack_forget()
            self.selectButton.config(text="Create", command=self._create)
            self.selectButton.bind("<Return>", self._create)
            self.selectButton.pack()
            self.promptEntry.focus_set()
            self._centerWindow()
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
        #self._centerWindow()
        self.selectList.focus_set()

    def _createEntry(self):
        context = self.promptEntry.get()
        newindex = self.db.add(context)
        self.db.save(self.keyid)
        self.results = self.db[newindex]
        self._selectAndReturn(self.results.keys()[0])

    ##########
    # These are meant to be bound to key events:

    def _query(self, event=None):
        self._search(self.promptEntry.get())
        self._selectDisplay()

    def _create(self, event=None):
        self._createEntry()

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
        if self.main:
            self.main.destroy()

    def returnValue(self):
        """Return user-selected search result of database query."""
        if self.master:
            self.master.wait_window(self.main)
        return self.selected
