package trie

import (
	"encoding/binary"
	"errors"
	"io"
)

func (mapping *DomainMap[T]) WriteBin(writer io.Writer, writeValue func(io.Writer, T) error) error {
	if mapping.IsEmpty() {
		return errors.New("empty domainMap")
	}

	// domainSet
	if err := mapping.index.DomainSet.WriteBin(writer); err != nil {
		return err
	}

	// separator
	if _, err := writer.Write([]byte{0}); err != nil {
		return err
	}

	// version
	if _, err := writer.Write([]byte{1}); err != nil {
		return err
	}

	// values
	if err := binary.Write(writer, binary.BigEndian, int64(len(mapping.values))); err != nil {
		return err
	}
	for _, value := range mapping.values {
		if err := writeValue(writer, value); err != nil {
			return err
		}
	}

	return nil
}

func ReadDomainMapBin[T any](reader io.Reader, readValue func(io.Reader) (T, error)) (*DomainMap[T], error) {
	// domainSet
	set, err := ReadDomainSetBin(reader)
	if err != nil {
		return nil, err
	}

	// separator
	separator := make([]byte, 1)
	if _, err := io.ReadFull(reader, separator); err != nil {
		return nil, err
	}
	if separator[0] != 0 {
		return nil, errors.New("separator is invalid")
	}

	// version
	version := make([]byte, 1)
	if _, err := io.ReadFull(reader, version); err != nil {
		return nil, err
	}
	if version[0] != 1 {
		return nil, errors.New("version is invalid")
	}

	// values
	var length int64
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length < 1 {
		return nil, errors.New("length is invalid")
	}
	mapping := &DomainMap[T]{values: make([]T, length)}
	mapping.index.DomainSet = set
	for index := range mapping.values {
		mapping.values[index], err = readValue(reader)
		if err != nil {
			return nil, err
		}
	}

	// init
	mapping.init()
	return mapping, nil
}
