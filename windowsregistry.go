package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RegistryValue describe a regkey value in a structure
type RegistryValue struct {
	key       registry.Key
	subKey    string
	valueName string
	value     string
}

// EnumRegistryPeristence get all the potential registry values used for persistence
func EnumRegistryPeristence() (values []RegistryValue, errors []error) {

	keys := []registry.Key{registry.USERS, registry.LOCAL_MACHINE}
	subkeys := []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`}

	for _, k := range keys {
		for _, s := range subkeys {
			v, err := EnumRegHivePersistence(k, s)
			if err != nil {
				errMsg := fmt.Errorf("%s\\%s - %s", GetRegistryHiveNameFromConst(k), s, err)
				errors = append(errors, errMsg)
			}

			for _, value := range v {
				values = append(values, value)
			}

		}
	}

	return values, errors
}

// GetRegistryHiveNameFromConst format registry.Key hive name as a string
func GetRegistryHiveNameFromConst(key registry.Key) string {
	if key == registry.CLASSES_ROOT {
		return "HKEY_CLASSES_ROOT"
	} else if key == registry.CURRENT_CONFIG {
		return "HKEY_CURRENT_CONFIG"
	} else if key == registry.CURRENT_USER {
		return "HKEY_CURRENT_USER"
	} else if key == registry.USERS {
		return "HKEY_USERS"
	} else if key == registry.LOCAL_MACHINE {
		return "HKEY_LOCAL_MACHINE"
	} else {
		return ""
	}
}

// EnumRegHivePersistence parse the specified key and subkey and return all string key/value in a []RegistryValue
func EnumRegHivePersistence(key registry.Key, subkey string) (values []RegistryValue, err error) {
	k, err := registry.OpenKey(key, "", registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}

	if key == registry.USERS {
		for _, s := range subkeys {
			if len(s) > 10 && !strings.HasSuffix(s, "_Classes") {
				v, err := enumRegSubKey(key, s+`\`+subkey)
				if err != nil {
					return nil, err
				}
				for _, item := range v {
					values = append(values, item)
				}

			}
		}
	} else {
		v, err := enumRegSubKey(key, subkey)
		if err != nil {
			return nil, err
		}
		for _, item := range v {
			values = append(values, item)
		}
	}

	return values, nil
}

// enumRegSubKey format subkey values in []RegistryValue
func enumRegSubKey(key registry.Key, subkey string) (values []RegistryValue, err error) {
	var (
		sk registry.Key
		sv []string
	)

	sk, err = registry.OpenKey(key, subkey, registry.READ)
	if err != nil {
		return nil, err
	}

	sv, err = sk.ReadValueNames(0)
	if err != nil {
		return nil, err
	}

	for _, item := range sv {
		v, _, _ := sk.GetStringValue(item)
		if len(v) > 0 {
			var result = RegistryValue{key: key, subKey: subkey, valueName: item, value: v}
			values = append(values, result)
		}
	}

	return values, nil
}
