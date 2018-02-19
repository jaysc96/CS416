package serverdfs

import (
	"log"
	"errors"
	"net/rpc"
)


type ChunkData struct {
	ChunkNum uint8
	Chunk [32]byte
	Fm *FMetaData
}

type FileID struct {
	Name string
	AuthorId string
}

// Metadata for each file
type FMetaData struct {
	Fid FileID
	Editors []*Client
	Version int
	IsWrite bool
}

// Each client has metadata for local files
type Client struct {
	Id string
	Ip string
	Port string
	IsConn bool
	LocalFiles []*FMetaData
}

type DFSServer interface {
	RegisterClient(c Client, id *string) error
	ExistsClient(c Client, exists *bool) error
	ReplaceClient(c Client, replaced *bool) error
	DisconnectClient (c Client, dis *bool) error
	ExistsFile(fid FileID, exists *bool) error
	OpenFile(Fid FileID, Fm *FMetaData) error
	CloseFile(Fid FileID, Fm *FMetaData) error
	ReadFile(cd ChunkData, read *bool) error
	WriteFile(cd ChunkData, write *bool) error
}

type DfsServer struct {
	Clients []Client
	Files map[string][]FMetaData
	ServerPort string
}

func (DfsS *DfsServer) RegisterClient(c Client, id *string) error {
	DfsS.Clients = append(DfsS.Clients, c)
	if DfsS.Files == nil {
		DfsS.Files = make(map[string][]FMetaData)
	}
	DfsS.Files[c.Id] = make([]FMetaData, 0)
	log.Printf("DFS Server: New client registered with ID [%s]", c.Id)
	return nil
}

func (DfsS *DfsServer) ExistsClient(c Client, exists *bool) error {
	for i := range DfsS.Clients {
		if DfsS.Clients[i].Id == c.Id {
			*exists = true
			return nil
		}
	}
	*exists = false
	return nil
}

func (DfsS *DfsServer) ReplaceClient(c Client, replaced *bool) error {
	for i := range DfsS.Clients {
		if DfsS.Clients[i].Id == c.Id {
			c.LocalFiles = append(c.LocalFiles, DfsS.Clients[i].LocalFiles...)
			DfsS.Clients[i] = c
			*replaced = true
			log.Printf("DFS Server: Client with ID [%s] replaced", c.Id)
			return nil
		}
	}
	*replaced = false
	return errors.New(c.Id)
}

func (DfsS *DfsServer) DisconnectClient(c *Client, dis *bool) error {
	cli := getClient(DfsS, c.Id)
	if cli.Id == "" {
		return errors.New("no client")
	}
	if !cli.IsConn {
		return errors.New("disconnected client")
	}
	log.Printf("DFS Server: Client [%s] disconnected", c.Id)
	cli.IsConn = false
	c.IsConn = false
	*dis = true
	return nil
}

func (DfsS *DfsServer) ExistsFile(fd FileID, exists *bool) error {
	for _, files := range DfsS.Files {
		for i := range files {
			if files[i].Fid.Name == fd.Name {
				*exists = true
				return nil
			}
		}
	}
	*exists = false
	return nil
}


func (DfsS *DfsServer) OpenFile(Fid FileID, fm *FMetaData) error {
	var exists bool
	DfsS.ExistsFile(Fid, &exists)
	isWrite := fm.IsWrite
	if exists {
		author := getAuthorID(DfsS, Fid.Name)
		fid := FileID{Fid.Name, author}
		*fm = getMetaData(DfsS, fid)
		cli := getClient(DfsS, author)
		if !cli.IsConn {
			return errors.New("disconnected")
		}
		if isWrite && fm.IsWrite {
			return errors.New("conflict")
		}
		fm.IsWrite = isWrite
		if fm.IsWrite {
			cli := getClient(DfsS, Fid.AuthorId)
			fm.Editors = append(fm.Editors, cli)
			fm.Version++
		}
		log.Printf("DFS Server: Existing file [%s] opened", Fid.Name)
	}
	if !exists {
		*fm = FMetaData{Fid, make([]*Client, 0), 0, isWrite}
		DfsS.Files[Fid.AuthorId] = append(DfsS.Files[Fid.AuthorId], *fm)
		for i := range DfsS.Clients {
			if DfsS.Clients[i].Id == Fid.AuthorId {
				DfsS.Clients[i].LocalFiles = append(DfsS.Clients[i].LocalFiles, fm)
			}
		}
		log.Printf("DFS Server: New file [%s] created", Fid.Name)
	}
	return nil
}

func (DfsS *DfsServer) CloseFile(fm FMetaData, closed *bool) error {
	log.Printf("DFS Server: File [%s] closed", fm.Fid.Name)
	return nil
}

func (DfsS *DfsServer) ReadFile(cd ChunkData, read *[32]byte) error {
	c := getClient(DfsS, cd.Fm.Fid.AuthorId)
	cAddr := c.Ip+c.Port
	cServ, err := rpc.Dial("tcp", cAddr)
	if err != nil {
		return err
	}
	sMethod := cd.Fm.Fid.Name+".Read"
	err = cServ.Call(sMethod, cd.ChunkNum, read)
	if err != nil {
		return err
	}
	return nil
}

func (DfsS *DfsServer) WriteFile(cd ChunkData, write *[32]byte) error {
	c := getClient(DfsS, cd.Fm.Fid.AuthorId)
	cAddr := c.Ip+c.Port
	cServ, err := rpc.Dial("tcp", cAddr)
	if err != nil {
		return err
	}
	sMethod := cd.Fm.Fid.Name+".Write"
	*write = cd.Chunk
	err = cServ.Call(sMethod, cd.ChunkNum, write)
	if err != nil {
		return err
	}
	return nil
}

func getAuthorID(dfss *DfsServer, fname string) string {
	for id, files := range dfss.Files {
		for i := range(files) {
			if files[i].Fid.Name == fname {
				return id
			}
		}
	}
	return ""
}

func getMetaData(dfss *DfsServer, fid FileID) FMetaData {
	for i := range dfss.Files[fid.AuthorId] {
		if dfss.Files[fid.AuthorId][i].Fid == fid {
			return dfss.Files[fid.AuthorId][i]
		}
	}
	return *new(FMetaData)
}

func getClient(dfss *DfsServer, id string) *Client {
	for i := range dfss.Clients {
		if dfss.Clients[i].Id == id {
			return &dfss.Clients[i]
		}
	}
	return new(Client)
}