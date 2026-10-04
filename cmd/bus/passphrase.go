package main

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"

	"github.com/kamune-org/kamune/pkg/storage"
)

// ErrSamePassphrase is returned by ChangePassphrase when the new
// passphrase is the current one.
var ErrSamePassphrase = errors.New(
	"the new passphrase is the same as the current one",
)

// ChangePassphrase changes the passphrase of the open database from
// oldPass to newPass, as storage.Storage.ChangePassphrase does: the
// database is re-encrypted under a new data key and its file rewritten,
// so the old passphrase opens neither the data written from now on nor
// the file, though it still opens copies made before. An empty oldPass
// stands for a database without a passphrase. An empty newPass removes
// the passphrase, once the user confirms that the database will not be
// protected; ChangePassphrase reports false when the user declines.
//
// The keychain entry for the database follows the change, since one
// that held the old passphrase would no longer open it: with
// saveToKeychain, newPass is saved there, or the empty one for a
// database without a passphrase; without it, any saved passphrase is
// removed.
//
// It refuses while anything uses the database (ErrStorageBusy), as
// changing the database does. A wrong oldPass changes nothing.
func (a *App) ChangePassphrase(
	oldPass, newPass string, saveToKeychain bool,
) (bool, error) {
	if a.store() == nil {
		return false, ErrStorageLocked
	}
	if oldPass == newPass {
		return false, ErrSamePassphrase
	}
	if newPass == "" && !a.confirm(
		"Remove the Database Passphrase?", noPassphraseWarning,
		"Remove Passphrase", "Cancel",
	) {
		return false, nil
	}

	a.unlockMu.Lock()
	defer a.unlockMu.Unlock()

	store := a.store()
	a.mu.RLock()
	busy := a.storageBusyLocked()
	path := a.dbPath
	a.mu.RUnlock()
	if store == nil {
		return false, ErrStorageLocked
	}
	if busy {
		return false, ErrStorageBusy
	}

	err := store.ChangePassphrase([]byte(oldPass), []byte(newPass))
	reopen := errors.Is(err, storage.ErrReopen)
	switch {
	case reopen:
	case errors.Is(err, storage.ErrWrongPassphrase):
		return false, &unlockError{
			msg: "The current passphrase is wrong", err: err,
		}
	case err != nil:
		return false, &unlockError{
			msg: "Could not change the passphrase: " + err.Error(),
			err: err,
		}
	}

	// From here on, newPass opens the database, even when the database
	// has to be opened again.
	a.mu.Lock()
	a.noPassphrase = newPass == ""
	a.mu.Unlock()
	a.updateSavedPassphrase(path, newPass, saveToKeychain)
	if newPass == "" {
		a.addLogEntry("WARN", "Removed the passphrase of the database: "+
			path+": anyone who can read its file can read it")
	} else {
		a.addLogEntry("INFO", "Changed the passphrase of the database: "+
			path)
	}

	if reopen {
		if err := a.reopenDB(store, path, []byte(newPass)); err != nil {
			return true, err
		}
	}
	a.emitEvent("db-passphrase-changed", newPass == "")
	return true, nil
}

// updateSavedPassphrase makes the keychain entry for the database at
// path follow a passphrase change to newPass; see ChangePassphrase.
func (a *App) updateSavedPassphrase(
	path, newPass string, saveToKeychain bool,
) {
	account := keychainAccount(path)
	if saveToKeychain {
		if err := keyring.Set(keychainService, account, newPass); err != nil {
			a.addLogEntry("WARN", "Failed to save the new passphrase "+
				"to the keychain: "+err.Error())
			a.emitEvent("toast", "The new passphrase was not saved "+
				"to the keychain: "+err.Error(), "warning")
		}
		return
	}
	err := keyring.Delete(keychainService, account)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		a.addLogEntry("WARN", "Failed to remove the old passphrase "+
			"from the keychain: "+err.Error())
		a.emitEvent("toast", "The old passphrase is still saved in the "+
			"keychain and no longer opens the database", "warning")
	}
}

// reopenDB closes old, the open database at path, and opens it again
// with passphrase, after a change that left old unusable
// (storage.ErrReopen). When the database does not open, none is open,
// and the user unlocks it as at startup.
func (a *App) reopenDB(
	old *storage.Storage, path string, passphrase []byte,
) error {
	a.storeMu.Lock()
	if a.db == old {
		a.db = nil
	}
	a.storeMu.Unlock()
	if err := old.Close(); err != nil {
		a.addLogEntry("WARN", "Failed to close database: "+err.Error())
	}

	store, err := a.openDB(path, passphrase, false)
	if err != nil {
		a.mu.Lock()
		a.pubKey = nil
		a.storageReady = false
		a.mu.Unlock()
		err = describeOpenError(err)
		a.setStorageError(err.Error())
		a.addLogEntry("ERROR", "The passphrase was changed, but the "+
			"database did not open again: "+err.Error())
		a.emitEvent("storage-locked")
		return fmt.Errorf("the passphrase was changed, but the "+
			"database did not open again: %w", err)
	}
	a.storeMu.Lock()
	a.db = store
	a.storeMu.Unlock()
	a.initFromStorage()
	return nil
}
