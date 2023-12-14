package managers

import "github.com/jackc/pgx/v5/pgxpool"

type DatabaseMgr interface {
	GetPool() *pgxpool.Pool
}

type DatabaseManager struct {
	Pool *pgxpool.Pool
}

func (dbMgr *DatabaseManager) GetPool() *pgxpool.Pool {
	return dbMgr.Pool
}

func NewDatabaseManager(pool *pgxpool.Pool) DatabaseMgr {
	return &DatabaseManager{Pool: pool}
}
