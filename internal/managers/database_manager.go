package managers

import (
	log "github.com/sirupsen/logrus"
	"server-alpha/internal/interfaces"
)

type DatabaseMgr interface {
	GetPool() interfaces.PgxPoolIface
}

type DatabaseManager struct {
	Pool interfaces.PgxPoolIface
}

func (dbMgr *DatabaseManager) GetPool() interfaces.PgxPoolIface {
	return dbMgr.Pool
}

func NewDatabaseManager(pool interfaces.PgxPoolIface) DatabaseMgr {
	log.Info("Initializing database manager")
	return &DatabaseManager{Pool: pool}
}
