package trie_test

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/trie"
	"github.com/stretchr/testify/assert"
)

func testDomainMapLookup[T any](test *testing.T, mapping *trie.DomainMap[T], query string) (T, bool) {
	test.Helper()
	value, found := mapping.Lookup(query)
	assert.Equal(test, found, mapping.DomainSet().Has(query), query)
	return value, found
}

func testDomainMapBin[T any](test *testing.T, mapping *trie.DomainMap[T]) *trie.DomainMap[T] {
	test.Helper()
	var buffer bytes.Buffer
	assert.NoError(test, mapping.WriteBin(&buffer, func(writer io.Writer, value T) error {
		return gob.NewEncoder(writer).Encode(value)
	}))
	restored, err := trie.ReadDomainMapBin(&buffer, func(reader io.Reader) (T, error) {
		var value T
		err := gob.NewDecoder(reader).Decode(&value)
		return value, err
	})
	assert.NoError(test, err)
	values := make(map[string]T)
	mapping.Foreach(func(domain string, value T) bool {
		values[domain] = value
		return true
	})
	restoredValues := make(map[string]T)
	restored.Foreach(func(domain string, value T) bool {
		restoredValues[domain] = value
		return true
	})
	assert.Equal(test, values, restoredValues)
	return restored
}

func TestDomainMapLifecycle(test *testing.T) {
	var nilBuilder *trie.DomainMapBuilder[int]
	assert.True(test, nilBuilder.IsEmpty())
	assert.Nil(test, nilBuilder.Build())

	var emptyMap trie.DomainMap[int]
	var nilMap *trie.DomainMap[int]
	for _, mapping := range []*trie.DomainMap[int]{nilMap, &emptyMap} {
		assert.True(test, mapping.IsEmpty())
		assert.Nil(test, mapping.DomainSet())
		value, found := testDomainMapLookup(test, mapping, "example.com")
		assert.False(test, found)
		assert.Zero(test, value)
		calls := 0
		mapping.Foreach(func(domain string, value int) bool {
			calls++
			return true
		})
		assert.Zero(test, calls)
		var buffer bytes.Buffer
		assert.Error(test, mapping.WriteBin(&buffer, func(writer io.Writer, value int) error {
			test.Error("empty map must not call the value encoder")
			return nil
		}))
		assert.Zero(test, buffer.Len())
	}

	var builder trie.DomainMapBuilder[int]
	assert.True(test, builder.IsEmpty())
	assert.Nil(test, builder.Build())
	for _, domain := range []string{
		"", ".", "..dev", "example.com.", " example.com", "example.com ",
		"invalid..example", "stun.+", "a.+.b", "a.+", "+", "+.+.com",
		"a+b.com", "a*b.com", "*a.com", "a*.com",
	} {
		assert.ErrorIs(test, builder.Insert(domain, 1), trie.ErrInvalidDomain, domain)
		assert.True(test, builder.IsEmpty(), domain)
	}

	assert.NoError(test, builder.Insert("+.example.com", 1))
	assert.NoError(test, builder.Insert("example.com", 2))
	assert.NoError(test, builder.Insert(".example.com", 3))
	assert.False(test, builder.IsEmpty())
	mapping := builder.Build()
	assert.False(test, mapping.IsEmpty())
	assert.True(test, builder.IsEmpty())
	assert.Nil(test, builder.Build())
	for query, expected := range map[string]int{"example.com": 2, "www.example.com": 3, "a.b.example.com": 3} {
		value, found := testDomainMapLookup(test, mapping, query)
		assert.True(test, found, query)
		assert.Equal(test, expected, value, query)
	}

	assert.NoError(test, builder.Insert("+.other.example", 0))
	next := builder.Build()
	assert.NoError(test, builder.Insert("reset.example", 4))
	builder.Reset()
	assert.True(test, builder.IsEmpty())
	assert.Nil(test, builder.Build())
	assert.NoError(test, builder.Insert("fresh.example", 5))
	fresh := builder.Build()
	value, found := testDomainMapLookup(test, fresh, "fresh.example")
	assert.True(test, found)
	assert.Equal(test, 5, value)
	value, found = testDomainMapLookup(test, fresh, "reset.example")
	assert.False(test, found)
	assert.Zero(test, value)

	value, found = testDomainMapLookup(test, mapping, "www.example.com")
	assert.True(test, found)
	assert.Equal(test, 3, value)
	_, found = testDomainMapLookup(test, mapping, "www.other.example")
	assert.False(test, found)
	_, found = testDomainMapLookup(test, mapping, "fresh.example")
	assert.False(test, found)
	value, found = testDomainMapLookup(test, next, "www.example.com")
	assert.False(test, found)
	assert.Zero(test, value)
	value, found = testDomainMapLookup(test, next, "www.other.example")
	assert.True(test, found)
	assert.Zero(test, value)
}

func TestDomainMapValues(test *testing.T) {
	var builder trie.DomainMapBuilder[[]int]
	assert.NoError(test, builder.Insert("+.example.com", []int{1}))
	assert.NoError(test, builder.Insert("+.EXAMPLE.COM", []int{2}))
	assert.NoError(test, builder.Insert("nil.example.com", nil))
	mapping := builder.Build()
	for _, mapping := range []*trie.DomainMap[[]int]{mapping, testDomainMapBin(test, mapping)} {
		for _, query := range []string{"example.com", "www.example.com", "WwW.ExAmPlE.CoM"} {
			value, found := testDomainMapLookup(test, mapping, query)
			assert.True(test, found, query)
			assert.Equal(test, []int{2}, value, query)
		}
		value, found := testDomainMapLookup(test, mapping, "nil.example.com")
		assert.True(test, found)
		assert.Nil(test, value)
		value, found = testDomainMapLookup(test, mapping, "missing.example")
		assert.False(test, found)
		assert.Nil(test, value)
		values := make(map[string][]int)
		mapping.Foreach(func(domain string, value []int) bool {
			values[domain] = value
			return true
		})
		assert.Equal(test, map[string][]int{
			"example.com":     {2},
			".example.com":    {2},
			"nil.example.com": nil,
		}, values)
	}

	var emptyBuilder trie.DomainMapBuilder[struct{}]
	assert.NoError(test, emptyBuilder.Insert("+.example.com", struct{}{}))
	empty := emptyBuilder.Build()
	for _, empty := range []*trie.DomainMap[struct{}]{empty, testDomainMapBin(test, empty)} {
		for query, expected := range map[string]bool{"example.com": true, "www.example.com": true, "a.b.example.com": true, "example.net": false} {
			_, found := testDomainMapLookup(test, empty, query)
			assert.Equal(test, expected, found, query)
		}
	}
}

func TestDomainMapLookup(test *testing.T) {
	rules := []struct {
		domain string
		value  string
	}{
		{".example.com", "suffix"},
		{"*.example.com", "single-label"},
		{"api.example.com", "api"},
		{"internal.*.example.com", "internal-service"},
		{"dead.a.example.com", "dead"},
		{"+.example.net", "net"},
		{".example.org", "org"},
		{"例子.测试", "unicode"},
		{"xn--fsqu00a.xn--0zwm56d", "punycode"},
		{"bücher.example", "books"},
		{"+.测试.cn", "unicode-suffix"},
		{"Mijia Cloud", "device"},
		{"_acme-challenge.example.com", "acme"},
		{"router", "local"},
	}
	var builder trie.DomainMapBuilder[string]
	for _, rule := range rules {
		assert.NoError(test, builder.Insert(rule.domain, rule.value))
	}
	mapping := builder.Build()
	for _, mapping := range []*trie.DomainMap[string]{mapping, testDomainMapBin(test, mapping)} {
		for query, expected := range map[string]string{
			"":                                   "",
			"api.example.com":                    "api",
			"API.EXAMPLE.COM":                    "api",
			"www.example.com":                    "single-label",
			"a.example.com":                      "single-label",
			"dead.a.example.com":                 "dead",
			"internal.service.example.com":       "internal-service",
			"other.service.example.com":          "suffix",
			"internal.other.service.example.com": "suffix",
			"example.com":                        "",
			"example.net":                        "net",
			"www.example.net":                    "net",
			"a.b.example.net":                    "net",
			"example.org":                        "",
			"www.example.org":                    "org",
			"example.test":                       "",
			"例子.测试":                              "unicode",
			"XN--FSQU00A.XN--0ZWM56D":            "punycode",
			"BÜCHER.EXAMPLE":                     "books",
			"测试.cn":                              "unicode-suffix",
			"www.测试.cn":                          "unicode-suffix",
			"日本語.测试":                             "",
			"Mijia Cloud":                        "device",
			"MIJIA CLOUD":                        "device",
			"_acme-challenge.example.com":        "acme",
			"ROUTER":                             "local",
		} {
			test.Run(query, func(test *testing.T) {
				value, found := testDomainMapLookup(test, mapping, query)
				assert.Equal(test, expected != "", found)
				assert.Equal(test, expected, value)
			})
		}
	}
}

func TestDomainMapWildcard(test *testing.T) {
	tests := []struct {
		domains []string
		queries map[string]int
	}{
		{
			[]string{"*.*.*.baidu.com", "www.baidu.*", "stun.*.*", "*.*.qq.com", "test.*.baidu.com", "*.apple.com"},
			map[string]int{
				"a.b.c.baidu.com":       1,
				"www.baidu.com":         2,
				"www.baidu.net":         2,
				"stun.ab.cd":            3,
				"test.test.qq.com":      4,
				"test.test.baidu.com":   5,
				"www.apple.com":         6,
				"test.baidu.com":        0,
				"a.b.baidu.com":         0,
				"d.a.b.c.baidu.com":     0,
				"stun.l.google.com":     0,
				"www.google.com":        0,
				"a.www.google.com":      0,
				"test.qq.com":           0,
				"test.test.test.qq.com": 0,
				"apple.com":             0,
				"a.www.apple.com":       0,
			},
		},
		{
			[]string{"*.dev", ".org", ".apple.*"},
			map[string]int{
				"example.dev":     1,
				"test.org":        2,
				"a.b.org":         2,
				"test.apple.com":  3,
				"test.apple.net":  3,
				"a.b.apple.com":   3,
				"dev":             0,
				"foo.example.dev": 0,
				"org":             0,
				"apple.com":       0,
				"test.orange.com": 0,
			},
		},
		{
			[]string{"*"},
			map[string]int{"router": 1, "com": 1, "example.com": 0, "": 0},
		},
		{
			[]string{"a.*", "*.a"},
			map[string]int{"a.com": 1, "b.a": 2, "a.a": 2, "a": 0, "com": 0, "www.a.com": 0},
		},
	}
	for _, testCase := range tests {
		test.Run(testCase.domains[0], func(test *testing.T) {
			var builder trie.DomainMapBuilder[int]
			for index, domain := range testCase.domains {
				assert.NoError(test, builder.Insert(domain, index+1))
			}
			mapping := builder.Build()
			for _, mapping := range []*trie.DomainMap[int]{mapping, testDomainMapBin(test, mapping)} {
				for query, expected := range testCase.queries {
					value, found := testDomainMapLookup(test, mapping, query)
					assert.Equal(test, expected != 0, found, query)
					assert.Equal(test, expected, value, query)
				}
			}
		})
	}
}

func TestDomainMapComplexWildcard(test *testing.T) {
	tests := []struct {
		domains []string
		queries map[string]int
	}{
		{
			[]string{"+.example.com", "example.com"},
			map[string]int{
				"example.com":     2,
				"www.example.com": 1,
			},
		},
		{
			[]string{"+.baidu.com", "+.a.baidu.com", "www.baidu.com", "+.bb.baidu.com"},
			map[string]int{
				"baidu.com":           1,
				"test.test.baidu.com": 1,
				"a.baidu.com":         2,
				"www.a.baidu.com":     2,
				"www.baidu.com":       3,
				"bb.baidu.com":        4,
				"www.bb.baidu.com":    4,
				"google.com":          0,
			},
		},
		{
			[]string{"+.stun.*.*", "+.stun.*.*.*", "+.stun.*.*.*.*", "stun.l.google.com"},
			map[string]int{
				"stun.website.com":               1,
				"global.stun.website.com":        1,
				"region.global.stun.website.com": 1,
				"global.stun.l.google.com":       2,
				"stun.a.b.example.com":           3,
				"global.stun.a.b.example.com":    3,
				"stun.l.google.com":              4,
				"stun.com":                       0,
				"stun.a.b.c.example.com":         0,
				"global.turn.website.com":        0,
			},
		},
		{
			[]string{"+.*", "stun.*.*.*"},
			map[string]int{
				"router":                   1,
				"example.com":              1,
				"stun.l.google.com":        2,
				"global.stun.l.google.com": 1,
				"":                         0,
			},
		},
	}
	for _, testCase := range tests {
		test.Run(testCase.domains[0], func(test *testing.T) {
			var builder trie.DomainMapBuilder[int]
			for index, domain := range testCase.domains {
				assert.NoError(test, builder.Insert(domain, index+1))
			}
			mapping := builder.Build()
			for _, mapping := range []*trie.DomainMap[int]{mapping, testDomainMapBin(test, mapping)} {
				for query, expected := range testCase.queries {
					value, found := testDomainMapLookup(test, mapping, query)
					assert.Equal(test, expected != 0, found, query)
					assert.Equal(test, expected, value, query)
				}
			}
		})
	}
}

func TestDomainMapWildcardShadow(test *testing.T) {
	tests := []struct {
		domains []string
		queries map[string]int
	}{
		{
			[]string{"*.example.com", "dead.a.example.com"},
			map[string]int{"a.example.com": 1, "b.a.example.com": 0, "dead.a.example.com": 2},
		},
		{
			[]string{"*.*.example.com", "dead.*.a.example.com", "dead.b.a.example.com"},
			map[string]int{
				"b.a.example.com":       1,
				"a.example.com":         0,
				"dead.c.a.example.com":  2,
				"dead.b.a.example.com":  3,
				"other.c.a.example.com": 0,
			},
		},
		{
			[]string{"*.*.*.example.com", "*.a.example.com"},
			map[string]int{"b.c.a.example.com": 1, "d.b.c.a.example.com": 0, "c.a.example.com": 2, "a.example.com": 0},
		},
	}
	for _, testCase := range tests {
		test.Run(testCase.domains[0], func(test *testing.T) {
			var builder trie.DomainMapBuilder[int]
			for index, domain := range testCase.domains {
				assert.NoError(test, builder.Insert(domain, index+1))
			}
			mapping := builder.Build()
			for _, mapping := range []*trie.DomainMap[int]{mapping, testDomainMapBin(test, mapping)} {
				for query, expected := range testCase.queries {
					value, found := testDomainMapLookup(test, mapping, query)
					assert.Equal(test, expected != 0, found, query)
					assert.Equal(test, expected, value, query)
				}
			}
		})
	}
}

func TestDomainMapLongDomain(test *testing.T) {
	prefix := strings.Repeat("label.", 32)
	var builder trie.DomainMapBuilder[int]
	assert.NoError(test, builder.Insert("+.example.com", 1))
	assert.NoError(test, builder.Insert(prefix+"example.com", 2))
	mapping := builder.Build()
	for _, mapping := range []*trie.DomainMap[int]{mapping, testDomainMapBin(test, mapping)} {
		for query, expected := range map[string]int{
			prefix + "example.com":          2,
			"www." + prefix + "example.com": 1,
			prefix + "example.net":          0,
		} {
			value, found := testDomainMapLookup(test, mapping, query)
			assert.Equal(test, expected != 0, found, query)
			assert.Equal(test, expected, value, query)
		}
	}
}

func TestDomainMapManyDomains(test *testing.T) {
	domains := make([]string, 2000)
	var builder trie.DomainMapBuilder[int]
	for index := range domains {
		domains[index] = fmt.Sprintf("host%d.example.com", index)
		assert.NoError(test, builder.Insert(domains[index], index+1))
	}
	mapping := builder.Build()
	for _, mapping := range []*trie.DomainMap[int]{mapping, testDomainMapBin(test, mapping)} {
		for index, domain := range domains {
			value, found := testDomainMapLookup(test, mapping, domain)
			assert.True(test, found, domain)
			assert.Equal(test, index+1, value, domain)
			query := "www." + domain
			value, found = testDomainMapLookup(test, mapping, query)
			assert.False(test, found, query)
			assert.Zero(test, value, query)
		}
		value, found := testDomainMapLookup(test, mapping, "missing.example.com")
		assert.False(test, found)
		assert.Zero(test, value)
	}
}

func TestDomainMapForeach(test *testing.T) {
	domains := []string{
		"google.com",
		"stun.*.*.*",
		"test.*.google.com",
		"+.baidu.com",
		"*.baidu.com",
		"*.*.baidu.com",
		"BAIDU.COM",
		".baidu.com",
		".example.org",
		"+.测试.cn",
		"bücher.example",
		"BÜCHER.EXAMPLE",
	}
	var builder trie.DomainMapBuilder[int]
	for index, domain := range domains {
		assert.NoError(test, builder.Insert(domain, index))
	}
	mapping := builder.Build()
	for _, mapping := range []*trie.DomainMap[int]{mapping, testDomainMapBin(test, mapping)} {
		for _, limit := range []int{1, 3} {
			calls := 0
			mapping.Foreach(func(domain string, value int) bool {
				calls++
				return calls < limit
			})
			assert.Equal(test, limit, calls)
		}

		var rebuilt trie.DomainMapBuilder[int]
		var mapDomains []string
		values := make(map[string]int)
		mapping.Foreach(func(domain string, value int) bool {
			assert.NotContains(test, values, domain)
			mapDomains = append(mapDomains, domain)
			values[domain] = value
			assert.NoError(test, rebuilt.Insert(domain, value))
			return true
		})
		assert.Equal(test, map[string]int{
			"google.com":        0,
			"stun.*.*.*":        1,
			"test.*.google.com": 2,
			"baidu.com":         6,
			".baidu.com":        7,
			"*.baidu.com":       4,
			"*.*.baidu.com":     5,
			".example.org":      8,
			"测试.cn":             9,
			".测试.cn":            9,
			"bücher.example":    11,
		}, values)
		var setDomains []string
		mapping.DomainSet().Foreach(func(domain string) bool {
			setDomains = append(setDomains, domain)
			return true
		})
		assert.ElementsMatch(test, mapDomains, setDomains)
		for _, mapping := range []*trie.DomainMap[int]{mapping, rebuilt.Build()} {
			for domain, expected := range map[string]int{"google.com": 0, "baidu.com": 6, "a.b.c.baidu.com": 7, "www.example.org": 8} {
				value, found := testDomainMapLookup(test, mapping, domain)
				assert.True(test, found, domain)
				assert.Equal(test, expected, value, domain)
			}
			value, found := testDomainMapLookup(test, mapping, "example.org")
			assert.False(test, found)
			assert.Zero(test, value)
		}
	}
}

type domainMapBenchmarkQuery struct {
	name  string
	keys  []string
	found bool
}

func domainMapLookupDomains(count int) []string {
	domains := make([]string, count)
	for index := range domains {
		domain := "host" + strconv.Itoa(index) + ".example.com"
		switch index % 5 {
		case 0:
			domains[index] = domain
		case 1:
			domains[index] = "+." + domain
		case 2:
			domains[index] = "." + domain
		case 3:
			domains[index] = "*." + domain
		case 4:
			domains[index] = "service.*." + domain
		}
	}
	return domains
}

func BenchmarkDomainMapLookup(benchmark *testing.B) {
	const deepDomain = "api.service.region.cluster.internal.prod.company.example.com"
	domains := append(domainMapLookupDomains(10000),
		"*.*.overlap.example.com",
		"dead.*.a.overlap.example.com",
		"dead.b.a.overlap.example.com",
		deepDomain,
		"例子.测试",
		"bücher.example",
		"xn--fsqu00a.xn--0zwm56d",
	)
	queries := []domainMapBenchmarkQuery{
		{"exact", []string{"host0.example.com", "HOST9995.EXAMPLE.COM"}, true},
		{"suffix", []string{"www.host1.example.com", "a.b.host2.example.com"}, true},
		{"wildcard", []string{"www.host3.example.com", "service.eu.host4.example.com"}, true},
		{"wildcard_fallback", []string{"b.a.overlap.example.com", "c.a.overlap.example.com"}, true},
		{"miss", []string{"host0.example.net", "www.host0.example.com", "other.eu.host4.example.com"}, false},
		{"deep", []string{deepDomain, "prod.eu-west-1.api.metrics.host1.example.com"}, true},
		{"unicode", []string{"例子.测试", "BÜCHER.EXAMPLE"}, true},
		{"punycode", []string{"xn--fsqu00a.xn--0zwm56d"}, true},
	}
	benchmark.Run("int", func(benchmark *testing.B) {
		benchmarkDomainMapLookup(benchmark, domains, queries, 1)
	})
	benchmark.Run("empty", func(benchmark *testing.B) {
		benchmarkDomainMapLookup(benchmark, domains, queries, struct{}{})
		benchmark.Run("set", func(benchmark *testing.B) {
			var builder trie.DomainSetBuilder
			for _, domain := range domains {
				assert.NoError(benchmark, builder.Insert(domain))
			}
			set := builder.Build()
			for _, query := range queries {
				benchmark.Run(query.name, func(benchmark *testing.B) {
					for _, key := range query.keys {
						assert.Equal(benchmark, query.found, set.Has(key), key)
					}
					benchmark.ReportAllocs()
					benchmark.ResetTimer()
					var found bool
					for iteration := 0; iteration < benchmark.N; iteration++ {
						found = set.Has(query.keys[iteration%len(query.keys)])
					}
					benchmark.StopTimer()
					runtime.KeepAlive(found)
				})
			}
		})
	})
}

func benchmarkDomainMapLookup[T any](benchmark *testing.B, domains []string, queries []domainMapBenchmarkQuery, value T) {
	benchmark.Run("map", func(benchmark *testing.B) {
		var builder trie.DomainMapBuilder[T]
		for _, domain := range domains {
			assert.NoError(benchmark, builder.Insert(domain, value))
		}
		mapping := builder.Build()
		for _, query := range queries {
			benchmark.Run(query.name, func(benchmark *testing.B) {
				for _, key := range query.keys {
					_, found := mapping.Lookup(key)
					assert.Equal(benchmark, query.found, found, key)
				}
				benchmark.ReportAllocs()
				benchmark.ResetTimer()
				var result T
				var found bool
				for iteration := 0; iteration < benchmark.N; iteration++ {
					result, found = mapping.Lookup(query.keys[iteration%len(query.keys)])
				}
				benchmark.StopTimer()
				runtime.KeepAlive(result)
				runtime.KeepAlive(found)
			})
		}
	})
	benchmark.Run("trie", func(benchmark *testing.B) {
		tree := trie.New[T]()
		for _, domain := range domains {
			assert.NoError(benchmark, tree.Insert(domain, value))
		}
		tree.Optimize()
		for _, query := range queries {
			benchmark.Run(query.name, func(benchmark *testing.B) {
				for _, key := range query.keys {
					assert.Equal(benchmark, query.found, tree.Search(key) != nil, key)
				}
				benchmark.ReportAllocs()
				benchmark.ResetTimer()
				var result T
				var found bool
				for iteration := 0; iteration < benchmark.N; iteration++ {
					node := tree.Search(query.keys[iteration%len(query.keys)])
					found = node != nil
					if found {
						result = node.Data()
					} else {
						var zero T
						result = zero
					}
				}
				benchmark.StopTimer()
				runtime.KeepAlive(result)
				runtime.KeepAlive(found)
			})
		}
	})
}

func BenchmarkDomainMapBuild(benchmark *testing.B) {
	for _, count := range []int{100, 10000} {
		domains := domainBuildBenchmarkDomains(count)
		benchmark.Run(fmt.Sprintf("%d/map", count), func(benchmark *testing.B) {
			benchmark.ReportAllocs()
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			benchmark.ResetTimer()
			var mapping *trie.DomainMap[int]
			for iteration := 0; iteration < benchmark.N; iteration++ {
				var builder trie.DomainMapBuilder[int]
				for _, domain := range domains {
					if err := builder.Insert(domain, 1); err != nil {
						benchmark.Fatal(err)
					}
				}
				mapping = builder.Build()
			}
			benchmark.StopTimer()
			runtime.GC()
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(domains)
			runtime.KeepAlive(mapping)
			benchmark.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained-B")
		})
		benchmark.Run(fmt.Sprintf("%d/trie", count), func(benchmark *testing.B) {
			benchmark.ReportAllocs()
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			benchmark.ResetTimer()
			var tree *trie.DomainTrie[int]
			for iteration := 0; iteration < benchmark.N; iteration++ {
				tree = trie.New[int]()
				for _, domain := range domains {
					if err := tree.Insert(domain, 1); err != nil {
						benchmark.Fatal(err)
					}
				}
				tree.Optimize()
			}
			benchmark.StopTimer()
			runtime.GC()
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(domains)
			runtime.KeepAlive(tree)
			benchmark.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained-B")
		})
	}
}
