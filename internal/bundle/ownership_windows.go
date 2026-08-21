//go:build windows

package bundle

import "os"

func finalizeArchive(file *os.File, partial, archive string, _ *sudoIdentity, _ []string) error {
	if err := file.Close(); err != nil {
		os.Remove(partial)
		return err
	}
	if err := os.Rename(partial, archive); err != nil {
		os.Remove(partial)
		return err
	}
	return nil
}
