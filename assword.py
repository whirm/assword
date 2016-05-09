import os
import io
import gpgme
import json
import time
import codecs
import datetime
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
from gi.repository import GObject
from gi.repository import Gdk

############################################################

DEFAULT_NEW_PASSWORD_OCTETS = 18

def pwgen(nbytes):
    """Return *nbytes* bytes of random data, base64-encoded."""
    s = os.urandom(nbytes)
    b = codecs.encode(s, 'base64')
    b = bytes(filter(lambda x: x not in b'=\n', b))
    return codecs.decode(b, 'ascii')

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

        If dbpath not specified, empty database will be initialized.

        The sigvalid property is set False if any OpenPGP signatures
        on the db file are invalid.  sigvalid is None for new
        databases.

        """
        self._dbpath = dbpath
        self._keyid = keyid

        # default database information
        self._type = 'assword'
        self._version = 1
        self._entries = {}

        self._gpg = gpgme.Context()
        self._gpg.armor = True
        self._sigvalid = None

        if self._dbpath and os.path.exists(self._dbpath):
            try:
                cleardata = self._decryptDB(self._dbpath)
                # FIXME: trap exception if json corrupt
                jsondata = json.loads(cleardata.getvalue().decode('utf-8'))
            except IOError as e:
                raise DatabaseError(e)
            except gpgme.GpgmeError as e:
                raise DatabaseError('Decryption error: %s' % (e[2]))

            # unpack the json data
            if 'type' not in jsondata or jsondata['type'] != self._type:
                raise DatabaseError('Database is not a proper assword database.')
            if 'version' not in jsondata or jsondata['version'] != self._version:
                raise DatabaseError('Incompatible database.')
            self._entries = jsondata['entries']

    @property
    def version(self):
        """Database version."""
        return self._version

    @property
    def sigvalid(self):
        """Validity of OpenPGP signature on db file."""
        return self._sigvalid

    def __str__(self):
        return '<assword.Database "%s">' % (self._dbpath)

    def __repr__(self):
        return 'assword.Database("%s")' % (self._dbpath)

    def __getitem__(self, context):
        """Return database entry for exact context."""
        return self._entries[context]

    def __contains__(self, context):
        """True if context string in database."""
        return context in self._entries

    def __iter__(self):
        """Iterator of all database contexts."""
        return iter(self._entries)

    def _decryptDB(self, path):
        data = io.BytesIO()
        with io.BytesIO() as encdata:
            with open(path, 'rb') as f:
                encdata.write(f.read())
                encdata.seek(0)
                sigs = self._gpg.decrypt_verify(encdata, data)
        # check signature
        if not sigs[0].validity >= gpgme.VALIDITY_FULL:
            self._sigvalid = False
        else:
            self._sigvalid = True
        data.seek(0)
        return data

    def _encryptDB(self, data, keyid):
        # The signer and the recipient are assumed to be the same.
        # FIXME: should these be separated?
        try:
            recipient = self._gpg.get_key(keyid or self._keyid)
            signer = self._gpg.get_key(keyid or self._keyid)
        except:
            raise DatabaseError('Could not retrieve GPG encryption key.')
        flags = gpgme.ENCRYPT_ALWAYS_TRUST
        try:
            flags |= gpgme.ENCRYPT_NO_COMPRESS
        except AttributeError:
            pass
        self._gpg.signers = [signer]
        encdata = io.BytesIO()
        data.seek(0)
        sigs = self._gpg.encrypt_sign([recipient],
                                      flags,
                                      data,
                                      encdata)
        encdata.seek(0)
        return encdata

    def _set_entry(self, context, password=None):
        if not isinstance(password, str):
            if password is None:
                bytes = DEFAULT_NEW_PASSWORD_OCTETS
            if isinstance(password, int):
                bytes = password
            password = pwgen(bytes)
        e = {'password': password,
             'date': datetime.datetime.now().isoformat()}
        self._entries[context] = e
        return e

    def add(self, context, password=None):
        """Add a new entry to the database.

        If password is None, one will be generated automatically.  If
        password is an int it will be interpreted as the number of
        random bytes to use.

        If the context is already in the db a DatabaseError will be
        raised.

        Database changes are not saved to disk until the save() method
        is called.

        """
        if context == '':
            raise DatabaseError("Can not add empty string context")
        if context in self:
            raise DatabaseError("Context already exists (see replace())")
        return self._set_entry(context, password)

    def replace(self, context, password=None):
        """Replace entry in database.

        If password is None, one will be generated automatically.  If
        password is an int it will be interpreted as the number of
        random bytes to use.

        If the context is not in the db a DatabaseError will be
        raised.

        Database changes are not saved to disk until the save() method
        is called.

        """
        if context not in self:
            raise DatabaseError("Context not found (see add())")
        return self._set_entry(context, password)

    def remove(self, context):
        """Remove an entry from the database.

        Database changes are not saved to disk until the save() method
        is called.

        """
        del self._entries[context]

    def save(self, keyid=None, path=None):
        """Save database to disk.

        Key ID must either be specified here or at database initialization.
        If path not specified, database will be saved at original dbpath location.

        """
        # FIXME: should check that recipient is not different than who
        # the db was originally encrypted for
        if not keyid:
            keyid = self._keyid
        if not keyid:
            raise DatabaseError('Key ID for decryption not specified.')
        if not path:
            path = self._dbpath
        if not path:
            raise DatabaseError('Save path not specified.')
        jsondata = {'type': self._type,
                    'version': self._version,
                    'entries': self._entries}
        cleardata = io.BytesIO(json.dumps(jsondata, indent=2).encode('utf-8'))
        encdata = self._encryptDB(cleardata, keyid)
        newpath = path + '.new'
        bakpath = path + '.bak'
        with open(newpath, 'wb') as f:
            f.write(encdata.getvalue())
        if os.path.exists(path):
            os.rename(path, bakpath)
        os.rename(newpath, path)

    def search(self, query=None):
        """Search for query in contexts.

        If query is None, all entries will be returned.

        """
        mset = {}
        for context, entry in self._entries.items():
            # simple substring match
            if query in context:
                mset[context] = entry
        return mset


############################################################
    
# Assumes that the func_data is set to the number of the text column in the
# model.
def _match_func(completion, key, iter, column):
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
                self.selected = r[list(r.keys())[0]]
                return

        self.window = Gtk.Window(Gtk.WindowType.TOPLEVEL)
        self.window.set_border_width(4)
        windowicon = self.window.render_icon(Gtk.STOCK_DIALOG_AUTHENTICATION, Gtk.IconSize.DIALOG)
        self.window.set_icon(windowicon)

        self.entry = Gtk.Entry()
        if query:
            self.entry.set_text(query)
        completion = Gtk.EntryCompletion()
        self.entry.set_completion(completion)
        liststore = Gtk.ListStore(GObject.TYPE_STRING)
        completion.set_model(liststore)
        completion.set_text_column(0)
        completion.set_match_func(_match_func, 0) # 0 is column number
        context_len = 50
        for context in self.db:
            if len(context) > context_len:
                context_len = len(context)
            liststore.append([context])
        hbox = Gtk.HBox()
        vbox = Gtk.VBox()
        self.button = Gtk.Button("Create")
        self.label = Gtk.Label(label="enter context for desired password:")
        self.window.add(vbox)

        if self.db.sigvalid is False:
            notification = Gtk.Label()
            msg = "WARNING: could not validate signature on db file"
            notification.set_markup('<span foreground="red">%s</span>' % msg)
            if len(msg) > context_len:
                context_len = len(msg)
            hsep = Gtk.HSeparator()
            vbox.add(notification)
            vbox.add(hsep)
            notification.show()
            hsep.show()

        vbox.add(self.label)
        vbox.pack_end(hbox, False, False, 0)
        hbox.add(self.entry)
        hbox.pack_end(self.button, False, False, 0)
        self.entry.set_width_chars(context_len)
        self.entry.connect("activate", self.retrieve)
        self.entry.connect("changed", self.update_button)
        self.button.connect("clicked", self.create)
        self.window.connect("destroy", self.destroy)
        self.window.connect("key-press-event", self.keypress)
    
        self.entry.show()
        self.label.show()
        vbox.show()
        hbox.show()
        self.button.show()
        self.update_button(self.entry)
        self.window.show()

    ##########

    @staticmethod
    def reset_signal(obj, signal, func=None):
        if hasattr(obj, '_callbacks'):
            if signal in obj._callbacks:
                cur = obj._callbacks[signal]
                obj.disconnect(cur)
                obj._callbacks.pop(signal)
        else:
            obj._callbacks = {}
        if func:
            hid = obj.connect(signal, func)
            obj._callbacks[signal] = hid

    ##########

    def keypress(self, widget, event):
        if event.keyval == Gdk.KEY_Escape:
            Gtk.main_quit()

    def update_button(self, widget, data=None):
        e = self.entry.get_text()
        self.button.set_sensitive(e != '' and e not in self.db)

    def retrieve(self, widget, data=None):
        e = self.entry.get_text()
        if e in self.db:
            self.selected = self.db[e]
            if self.selected is None:
                self.label.set_text("weird -- no context found even though we thought there should be one")
            else:
                Gtk.main_quit()
        else:
            self.label.set_text("no match")

    def create(self, widget, data=None):
        e = self.entry.get_text()
        self.selected = self.db.add(e)
        self.db.save()
        Gtk.main_quit()

    def destroy(self, widget, data=None):
        Gtk.main_quit()

    def returnValue(self):
        if self.selected is None:
            Gtk.main()
        return self.selected
