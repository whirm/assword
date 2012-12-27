import os
import io
import gpgme
import tarfile
import tempfile

class Entry():
    """A gpass database entry."""

    def __init__(self, db, index):
        self.db = db
        self.index = index

    def getContext(self):
        """Get context text for entry."""
        cpath = os.path.join(self.index, 'context')
        f = self.db.fopen(cpath)
        context = f.read()
        f.close()
        return context.strip()

    def getPassword(self):
        """Get password for entry."""
        ppath = os.path.join(self.index, 'password')
        f = self.db.fopen(ppath)
        password = f.read()
        f.close()
        return password

class Database():
    """A gpass database."""

    def __init__(self, path, writable=False):
        self.path = path
        # database is directory
        if os.path.isdir(self.path):
            # FIXME: support encfs
            self.root = self.path
            self.istar = False
        # database is tar file
        else:
            if writable:
                mode = 'a'
            else:
                mode = 'r'

            self.gpg = gpgme.Context()
            if os.path.exists(self.path):
                self.tardata = self._decryptDB(self.path)
            else:
                self.tardata = io.BytesIO()
            self.root = tarfile.open(fileobj=self.tardata, mode=mode)

            self.istar = True

    def _decryptDB(self, path):
        data = io.BytesIO()
        with io.BytesIO() as encdata:
            with open(path, 'rb') as f:
                # read in the encrypted tar ball
                encdata.write(f.read())
                encdata.seek(0)
                # decrypt
                self.gpg.decrypt(encdata, data)
        data.seek(0)
        return data

    def _encryptDB(self, data):
        recipient = self.gpg.get_key(os.getenv('PGPID'))
        encdata = io.BytesIO()
        data.seek(0)
        self.gpg.encrypt([recipient],
                         gpgme.ENCRYPT_ALWAYS_TRUST,
                         data,
                         encdata)
        encdata.seek(0)
        return encdata

    def save(self):
        """Save a modified database."""
        if self.istar:
            self.root.close()
            encdata = self._encryptDB(self.tardata)
            self.tardata.close()
            if os.path.exists(self.path):
                os.rename(self.path, self.path + '.bak')
            with open(self.path, 'w') as f:
                f.write(encdata.getvalue())

    def _fopen(self, rpath):
        if self.istar:
            f = self.root.extractfile(rpath)
        else:
            f = open(os.path.join(self.root, rpath), 'r')
        return f

    def _entries(self):
        if self.istar:
            dirs = []
            for mem in self.root:
                if mem.isdir():
                    dirs.append(mem.name)
        else:
            for root, dirs, files in os.walk(self.root):
                break
        return sorted(dirs)

    def search(self, query=None):
        """Search the database for string."""
        query = ' '.join(query)
        mset = []
        for index in self._entries():
            entry = Entry(self, index)
            if query:
                context = entry.getContext()
                if query in context:
                    mset.append(entry)
            else:
                mset.append(entry)
        return mset

    def _newindex(self):
        indicies = [int(entry) for entry in self._entries()]
        if not indicies:  indicies = [-1]
        return '%08d' % (max(indicies) + 1)

    def add(self, context, password):
        """Add a new entry to the database."""
        newindex = self._newindex()
        tempdir = tempfile.mkdtemp(prefix='gpass-')
        cpath = os.path.join(tempdir, 'context')
        ppath = os.path.join(tempdir, 'password')
        with open(cpath, 'w') as f:
            f.write(context.strip())
        with open(ppath, 'w') as f:
            f.write(password.strip())
        if self.istar:
            self.root.add(tempdir, arcname=newindex)
            os.remove(cpath)
            os.remove(ppath)
            os.removedirs(tempdir)
        else:
             os.rename(tempdir, os.path.join(self.root, newindex))
        return newindex
