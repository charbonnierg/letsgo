package stores

type Store interface {
	GetToken() (string, error)
}

type Stores struct {
	Files       Store
	Environment Store
	Keyvault    Store
}

func (s *Stores) GetFileStore() Store {
	return s.Files
}

func (s *Stores) GetEnvStore() Store {
	return s.Environment
}
func (s *Stores) GetKeyvaultStore() Store {
	return s.Keyvault
}

func NewStores() Stores {
	return Stores{
		Keyvault:    &KeyVault{},
		Files:       &FileStore{},
		Environment: &EnvStore{},
	}
}
