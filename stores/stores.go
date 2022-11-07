package stores

// A store expose the GetToken() method
// This method may return an error
type Store interface {
	GetToken() (string, error)
}

// Stores used to find DNS auth token
type Stores struct {
	Files       Store
	Environment Store
	Keyvault    Store
}

// Access the file store
func (s *Stores) GetFileStore() Store {
	return s.Files
}

// Access the env store
func (s *Stores) GetEnvStore() Store {
	return s.Environment
}

// Access the keyvault store
func (s *Stores) GetKeyvaultStore() Store {
	return s.Keyvault
}

// Default stores
func DefaultStores() Stores {
	return Stores{
		Keyvault:    &KeyVault{},
		Files:       &FileStore{},
		Environment: &EnvStore{},
	}
}
