//go:build !windows

package bundle

import "os"

func applyOwnership(archive string, createdDirs []string, uid, gid int) error {
	if err := os.Chown(archive, uid, gid); err != nil {
		return err
	}
	for _, directory := range createdDirs {
		if err := os.Chown(directory, uid, gid); err != nil {
			return err
		}
	}
	return nil
}
