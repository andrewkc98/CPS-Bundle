//go:build !windows

package bundle

import (
	"fmt"
	"os"
)

func finalizeArchive(file *os.File, partial, archive string, identity *sudoIdentity, createdDirs []string) error {
	// The paths share a directory, so Link atomically publishes a second name for
	// the completed archive and never replaces an existing destination. From this
	// point onward, publication has succeeded; later ownership or close failures
	// leave the archive in place and must be reported as such.
	if err := os.Link(partial, archive); err != nil {
		file.Close()
		os.Remove(partial)
		if os.IsExist(err) {
			return fmt.Errorf("archive exists at %s and was not replaced: %w", archive, err)
		}
		return err
	}
	if err := os.Remove(partial); err != nil {
		file.Close()
		return fmt.Errorf("archive exists at %s, but temporary cleanup failed: %w", archive, err)
	}
	if identity != nil {
		if err := file.Chown(identity.uid, identity.gid); err != nil {
			file.Close()
			return fmt.Errorf("archive exists at %s, but ownership correction failed: %w", archive, err)
		}
		for _, directory := range createdDirs {
			if err := os.Chown(directory, identity.uid, identity.gid); err != nil {
				file.Close()
				return fmt.Errorf("archive exists at %s, but ownership correction failed: %w", archive, err)
			}
		}
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("archive exists at %s, but final close failed: %w", archive, err)
	}
	return nil
}
