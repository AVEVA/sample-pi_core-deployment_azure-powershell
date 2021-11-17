USE [PIFD]
GO
ALTER ROLE [db_AFServer] DROP MEMBER [AFServers]
GO
ALTER AUTHORIZATION ON SCHEMA::[AFServers] TO [AFQueryEngines]
GO
DROP USER [AFServers]
GO
CREATE USER [AFServers] FOR LOGIN $(domainAccount)
GO
ALTER ROLE [db_AFServer] ADD MEMBER [AFServers]
GO
ALTER AUTHORIZATION ON SCHEMA::[AFServers] TO [AFServers]
GO
USE [master]
GO
IF EXISTS (SELECT loginname FROM master.dbo.syslogins WHERE name = '$(serverAccount)')
DROP LOGIN [$(serverAccount)]
GO
