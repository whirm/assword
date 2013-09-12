import os
import io
import gpgme
import json
import time
import base64
import datetime
import pygtk
pygtk.require('2.0')
import gtk
import gobject

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
            raise DatabaseError('Signature on database was not fully valid.')
        data.seek(0)
        return data

    def _encryptDB(self, data, keyid):
        # The signer and the recipient are assumed to be the same.
        # FIXME: should these be separated?
        try:
            recipient = self.gpg.get_key(keyid or self.keyid)
            signer = self.gpg.get_key(keyid or self.keyid)
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
    
# Assumes that the func_data is set to the number of the text column in the
# model.
def match_func(completion, key, iter, column):
    model = completion.get_model()
    text = model[iter][column]
    if text.lower().find(key.lower()) > -1:
        return True
    return False

class Gui:
    """Assword X-based query UI."""
    def __init__(self, db, query=None):

        self.db = db
        self.query = None
        self.results = None
        self.selected = None
        self.window = None
        self.entry = None
        self.label = None

        if query:
            # If we have an intial query, directly do a search without
            # initializing any X objects.  This will initialize the
            # database and potentially return entries.
            r = self.db.search(query)
            # If only a single entry is found, _search() will set the
            # result and attempt to close any X objects (of which
            # there are none).  Since we don't need to initialize any
            # GUI, return the initialization immediately.
            # See .returnValue().
            if len(r) == 1:
                self.selected = r[r.keys()[0]]
                return

        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_border_width(10)

        self.entry = gtk.Entry()
        if query:
            self.entry.set_text(query)
        completion = gtk.EntryCompletion()
        self.entry.set_completion(completion)
        liststore = gtk.ListStore(gobject.TYPE_STRING)
        completion.set_model(liststore)
        completion.set_text_column(0)
        completion.set_match_func(match_func, 0) # 0 is column number
        for context in self.db.entries:
            liststore.append([context])
        hbox = gtk.HBox()
        vbox = gtk.VBox()
        self.createbutton = gtk.Button("Create")
        self.label = gtk.Label("enter the context for the password you want:")
        self.window.add(vbox)

        vbox.add(self.label)
        vbox.add(hbox)
        hbox.add(self.entry)
        hbox.add(self.createbutton)

        self.entry.connect("activate", self.enter)
        self.entry.connect("changed", self.updatecreate)
        self.createbutton.connect("clicked", self.create)
        self.window.connect("destroy", self.destroy)
        self.window.connect("key-press-event", self.keypress)
    
        self.entry.show()
        self.label.show()
        vbox.show()
        hbox.show()
        self.createbutton.show()
        self.updatecreate(self.entry)
        self.window.show()

    def keypress(self, widget, event):
        if event.keyval == gtk.keysyms.Escape:
            gtk.main_quit()

    def updatecreate(self, widget, data=None):
        e = self.entry.get_text()
        self.createbutton.set_sensitive(e != '' and e not in self.db.entries)

    def enter(self, widget, data=None):
        e = self.entry.get_text()
        if e in self.db.entries:
            self.selected = self.db[e]
            if self.selected is None:
                self.label.set_text("weird -- no context found even though we thought there should be one")
            else:
                gtk.main_quit()
        else:
            self.label.set_text("no match")

    def create(self, widget, data=None):
        e = self.entry.get_text()
        self.selected = self.db.add(e)
        self.db.save()
        gtk.main_quit()

    def destroy(self, widget, data=None):
        gtk.main_quit()

    def returnValue(self):
        if self.selected is None:
            gtk.main()
        return self.selected
