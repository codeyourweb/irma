package main

import (
	"fmt"
	"log"
	"os"

	golnk "github.com/parsiya/golnk"
)

// ListStartMenuFolders return a []string of all available StartMenu folders
func ListStartMenuFolders() (startMenu []string, err error) {
	var usersDir []string

	startMenu = append(startMenu, os.Getenv("SystemDrive")+`\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`)

	usersDir, err = RetrivesFilesFromUserPath(os.Getenv("SystemDrive")+`\Users`, false, nil, false)
	if err != nil {
		return startMenu, err
	}

	for _, uDir := range usersDir {
		startMenu = append(startMenu, uDir+`\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
	}

	return startMenu, err
}

// ListStartMenuLnkPersistence check for every *.lnk in Windows StartMenu folders and extract every executable path in those links
func ListStartMenuLnkPersistence() (exePath []string, errors []error) {

	startMenuFolders, err := ListStartMenuFolders()
	if err != nil {
		log.Println(err)
	}

	for _, path := range startMenuFolders {

		files, err := RetrivesFilesFromUserPath(path, true, []string{".lnk"}, false)

		if err != nil {
			fmt.Errorf("%s - %s", path, err)
		}

		for _, p := range files {
			lnk, lnkErr := golnk.File(p)
			// Print errors and move on to the next file.
			if lnkErr != nil {
				errors = append(errors, fmt.Errorf("%s - Lnk parse error", p))
				continue
			}

			exePath = append(exePath, lnk.LinkInfo.LocalBasePath)
		}
	}

	return exePath, errors
}
