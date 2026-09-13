package trie

import (
	"strings"
	"unicode/utf8"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/openacid/low/bitmap"
)

const domainMapSelectOverflow = ^uint8(0)

// DomainMap is an immutable domain-pattern index with values. Lookup prefers
// exact labels, then single-label wildcards, then suffix wildcards.
// The zero value and a nil *DomainMap are empty. Values are copied, not deep-copied.
type DomainMap[T any] struct {
	index     domainMapIndex
	leafRanks []int32
	values    []T
}

type domainMapIndex struct {
	*DomainSet
	selectDeltas []uint8
}

// DomainMapBuilder collects patterns and values. Its zero value is ready to use.
// Insert and Build must not run concurrently on the same builder.
type DomainMapBuilder[T any] struct {
	set       DomainSetBuilder
	valueKeys map[string]T
}

// Insert accepts the same patterns as DomainTrie.Insert. The last insertion wins
// for each expanded terminal; +.domain assigns both the exact and suffix values.
func (builder *DomainMapBuilder[T]) Insert(domain string, value T) error {
	begin := len(builder.set.keys)
	if err := builder.set.Insert(domain); err != nil {
		return err
	}
	if builder.valueKeys == nil {
		builder.valueKeys = make(map[string]T)
	}
	for _, key := range builder.set.keys[begin:] {
		builder.valueKeys[key] = value
	}
	return nil
}

// IsEmpty reports whether the builder has any domain paths. A nil builder is empty.
func (builder *DomainMapBuilder[T]) IsEmpty() bool {
	return builder == nil || builder.set.IsEmpty()
}

// Reset discards pending patterns and values without changing previously built maps.
func (builder *DomainMapBuilder[T]) Reset() {
	builder.set.Reset()
	builder.valueKeys = nil
}

// Build consumes the builder's inputs and creates an immutable map. It returns nil
// for an empty or nil builder. The builder can be reused without changing earlier maps.
func (builder *DomainMapBuilder[T]) Build() *DomainMap[T] {
	if builder == nil {
		return nil
	}
	keys, valueKeys := builder.set.keys, builder.valueKeys
	builder.Reset()
	if len(keys) == 0 {
		return nil
	}
	mapping := &DomainMap[T]{values: make([]T, 0, len(valueKeys))}
	mapping.index.DomainSet = buildDomainSet(keys, func(key string) {
		mapping.values = append(mapping.values, valueKeys[key])
	})
	mapping.init()
	return mapping
}

// IsEmpty reports whether the map contains any values. A nil map is empty.
func (mapping *DomainMap[T]) IsEmpty() bool {
	return mapping == nil || len(mapping.values) == 0
}

// DomainSet returns the underlying domain set without copying it.
// The returned set is read-only. A zero or nil map returns nil.
func (mapping *DomainMap[T]) DomainSet() *DomainSet {
	if mapping == nil {
		return nil
	}
	return mapping.index.DomainSet
}

// Lookup returns the most specific matching value and whether it was found.
// A stored zero or nil value is still a match. Like DomainSet.Has, Lookup matches
// names without validating query syntax.
func (mapping *DomainMap[T]) Lookup(domain string) (T, bool) {
	var zero T
	if mapping.IsEmpty() {
		return zero, false
	}
	nodeID := mapping.index.match(0, domain)
	if nodeID < 0 {
		return zero, false
	}
	rank, _ := bitmap.Rank64(mapping.index.leaves, mapping.leafRanks, int32(nodeID))
	return mapping.values[rank], true
}

// Foreach iterates over the stored domain patterns and their associated values
// in unspecified order. Patterns use lowercase labels, "*" for a single-label
// wildcard, and a leading "." for subdomain-only matching. Exact and suffix-only
// patterns are separate entries; "+." shorthand is not emitted. Each pattern
// and its value can be passed to DomainMapBuilder.Insert independently to
// reproduce the mappings. Returning false stops iteration. Empty or nil maps
// do not call fn.
func (mapping *DomainMap[T]) Foreach(fn func(domain string, value T) bool) {
	if mapping.IsEmpty() {
		return
	}
	mapping.index.keys(func(key string, nodeID int) bool {
		rank, _ := bitmap.Rank64(mapping.index.leaves, mapping.leafRanks, int32(nodeID))
		// Internal keys are reversed, with a trailing '+' for suffix wildcards.
		// Removing that marker leaves the leading-dot syntax after reversal.
		return fn(utils.Reverse(strings.TrimSuffix(key, complexWildcard)), mapping.values[rank])
	})
}

// init builds pre-calculated cache to speed up rank() and select()
func (mapping *DomainMap[T]) init() {
	mapping.leafRanks = bitmap.IndexRank64(mapping.index.leaves)
	mapping.index.initSelectDeltas()
}

func (index *domainMapIndex) initSelectDeltas() {
	index.selectDeltas = make([]uint8, len(index.labels))
	for ordinal := range index.selectDeltas {
		position := selectIthOne(index.labelBitmap, index.ranks, index.selects, ordinal)
		delta := position - int(index.selects[ordinal>>5])
		if delta < 0 || delta >= int(domainMapSelectOverflow) {
			index.selectDeltas[ordinal] = domainMapSelectOverflow
		} else {
			index.selectDeltas[ordinal] = uint8(delta)
		}
	}
}

func (index *domainMapIndex) childStart(ordinal int, delta uint8) int {
	if delta == domainMapSelectOverflow {
		return index.uncachedChildStart(ordinal)
	}
	return int(index.selects[ordinal>>5]) + int(delta) + 1
}

func (index *domainMapIndex) uncachedChildStart(ordinal int) int {
	return selectIthOne(index.labelBitmap, index.ranks, index.selects, ordinal) + 1
}

// match consumes one domain label per recursive step, like DomainTrie.search.
// Each branch gets its own remaining prefix, so failed matches cannot consume it.
func (index *domainMapIndex) match(nodeID int, domain string) int {
	if domain == "" {
		if getBit(index.leaves, nodeID) != 0 {
			return nodeID
		}
		return -1
	}
	bitmapIndex := 0
	if nodeID > 0 {
		bitmapIndex = index.childStart(nodeID-1, index.selectDeltas[nodeID-1])
		for getBit(index.labelBitmap, bitmapIndex) == 0 && index.labels[bitmapIndex-nodeID] < domainStepByte {
			bitmapIndex++
		}
		if getBit(index.labelBitmap, bitmapIndex) != 0 || index.labels[bitmapIndex-nodeID] != domainStepByte {
			return -1
		}
		nodeID = bitmapIndex - nodeID + 1
		bitmapIndex = index.childStart(nodeID-1, index.selectDeltas[nodeID-1])
	}
	separator := strings.LastIndexByte(domain, domainStepByte)
	part := domain[separator+1:]
	remaining := ""
	if separator >= 0 {
		remaining = domain[:separator]
	}
	for offset := 0; offset < len(part); offset++ {
		if part[offset] >= utf8.RuneSelf {
			part = byteReverse(strings.ToLower(utils.Reverse(part)))
			break
		}
	}
	staticNode, staticIndex := nodeID, bitmapIndex
	for offset := 0; offset < len(part); offset++ {
		label := revLowerAt(part, offset)
		for getBit(index.labelBitmap, staticIndex) == 0 && index.labels[staticIndex-staticNode] < label {
			staticIndex++
		}
		if getBit(index.labelBitmap, staticIndex) != 0 || index.labels[staticIndex-staticNode] != label || label == complexWildcardByte {
			staticNode = -1
			break
		}
		staticNode = staticIndex - staticNode + 1
		if offset+1 < len(part) {
			staticIndex = index.childStart(staticNode-1, index.selectDeltas[staticNode-1])
		}
	}
	if staticNode >= 0 {
		if terminal := index.match(staticNode, remaining); terminal >= 0 {
			return terminal
		}
	}
	for getBit(index.labelBitmap, bitmapIndex) == 0 {
		label := index.labels[bitmapIndex-nodeID]
		childID := bitmapIndex - nodeID + 1
		switch label {
		case wildcardByte:
			if part != wildcard {
				if terminal := index.match(childID, remaining); terminal >= 0 {
					return terminal
				}
			}
		case complexWildcardByte:
			return childID
		}
		if label > complexWildcardByte {
			break
		}
		bitmapIndex++
	}
	return -1
}
