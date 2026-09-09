package trie_test

import (
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/metacubex/mihomo/component/trie"
	"github.com/stretchr/testify/assert"
)

func testDump(t *testing.T, tree *trie.DomainTrie[struct{}], set *trie.DomainSet) {
	var dataSrc []string
	tree.Foreach(func(domain string, data struct{}) bool {
		dataSrc = append(dataSrc, domain)
		return true
	})
	slices.Sort(dataSrc)
	var dataSet []string
	set.Foreach(func(key string) bool {
		dataSet = append(dataSet, key)
		return true
	})
	slices.Sort(dataSet)
	assert.Equal(t, dataSrc, dataSet)
}

func TestDomainSet(t *testing.T) {
	tree := trie.New[struct{}]()
	var builder trie.DomainSetBuilder
	domainSet := []string{
		"baidu.com",
		"google.com",
		"www.google.com",
		"test.a.net",
		"test.a.oc",
		"Mijia Cloud",
		".qq.com",
		"+.cn",
	}

	for _, domain := range domainSet {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
		assert.NoError(t, builder.Insert(domain))
	}
	assert.False(t, builder.IsEmpty())
	set := builder.Build()
	assert.Equal(t, tree.NewDomainSet(), set)
	assert.NotNil(t, set)
	assert.True(t, set.Has("test.cn"))
	assert.True(t, set.Has("cn"))
	assert.True(t, set.Has("Mijia Cloud"))
	assert.True(t, set.Has("test.a.net"))
	assert.True(t, set.Has("www.qq.com"))
	assert.True(t, set.Has("google.com"))
	assert.False(t, set.Has("qq.com"))
	assert.False(t, set.Has("www.baidu.com"))
	testDump(t, tree, set)
}

func TestDomainSetBuilderLifecycle(t *testing.T) {
	var builder trie.DomainSetBuilder
	assert.True(t, builder.IsEmpty())
	assert.ErrorIs(t, builder.Insert("invalid..example"), trie.ErrInvalidDomain)
	assert.True(t, builder.IsEmpty())
	assert.Nil(t, builder.Build())

	for _, domain := range []string{"+.example.com", "example.com", "+.example.com"} {
		assert.NoError(t, builder.Insert(domain))
	}
	set := builder.Build()
	assert.True(t, builder.IsEmpty())
	assert.True(t, set.Has("example.com"))
	assert.True(t, set.Has("www.example.com"))

	var keys []string
	set.Foreach(func(key string) bool {
		keys = append(keys, key)
		return true
	})
	slices.Sort(keys)
	assert.Equal(t, []string{"+.example.com", "example.com"}, keys)

	assert.NoError(t, builder.Insert("other.example"))
	set = builder.Build()
	assert.True(t, set.Has("other.example"))
	assert.False(t, set.Has("example.com"))

	assert.NoError(t, builder.Insert("discard.example"))
	builder.Reset()
	assert.True(t, builder.IsEmpty())
	assert.Nil(t, builder.Build())
}

func TestDomainSetComplexWildcard(t *testing.T) {
	tree := trie.New[struct{}]()
	var builder trie.DomainSetBuilder
	domainSet := []string{
		"+.baidu.com",
		"+.a.baidu.com",
		"www.baidu.com",
		"+.bb.baidu.com",
		"test.a.net",
		"test.a.oc",
		"www.qq.com",
	}

	for _, domain := range domainSet {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
		assert.NoError(t, builder.Insert(domain))
	}
	assert.False(t, builder.IsEmpty())
	set := builder.Build()
	assert.Equal(t, tree.NewDomainSet(), set)
	assert.NotNil(t, set)
	assert.False(t, set.Has("google.com"))
	assert.True(t, set.Has("www.baidu.com"))
	assert.True(t, set.Has("test.test.baidu.com"))
	testDump(t, tree, set)
}

func TestDomainSetWildcard(t *testing.T) {
	tree := trie.New[struct{}]()
	var builder trie.DomainSetBuilder
	domainSet := []string{
		"*.*.*.baidu.com",
		"www.baidu.*",
		"stun.*.*",
		"*.*.qq.com",
		"test.*.baidu.com",
		"*.apple.com",
	}

	for _, domain := range domainSet {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
		assert.NoError(t, builder.Insert(domain))
	}
	assert.False(t, builder.IsEmpty())
	set := builder.Build()
	assert.Equal(t, tree.NewDomainSet(), set)
	assert.NotNil(t, set)
	assert.True(t, set.Has("www.baidu.com"))
	assert.True(t, set.Has("test.test.baidu.com"))
	assert.True(t, set.Has("test.test.qq.com"))
	assert.True(t, set.Has("stun.ab.cd"))
	assert.False(t, set.Has("test.baidu.com"))
	assert.False(t, set.Has("www.google.com"))
	assert.False(t, set.Has("a.www.google.com"))
	assert.False(t, set.Has("test.qq.com"))
	assert.False(t, set.Has("test.test.test.qq.com"))
	testDump(t, tree, set)
}

func TestDomainSetCase(t *testing.T) {
	tree := trie.New[struct{}]()
	var builder trie.DomainSetBuilder
	for _, domain := range []string{"example.com", "EXAMPLE.COM", "+.mixed.example.org"} {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
		assert.NoError(t, builder.Insert(domain))
	}
	set := builder.Build()
	assert.Equal(t, tree.NewDomainSet(), set)
	assert.NotNil(t, set)
	assert.True(t, set.Has("EXAMPLE.COM"))
	assert.True(t, set.Has("ExAmPlE.cOm"))
	assert.True(t, set.Has("WWW.MIXED.EXAMPLE.ORG"))
	assert.False(t, set.Has("EXAMPLE.NET"))
}

// TestDomainSetUnicode covers keys that are not ASCII, which take a different
// path than the byte-wise one because the set is built with rune-wise reversal.
func TestDomainSetUnicode(t *testing.T) {
	tree := trie.New[struct{}]()
	var builder trie.DomainSetBuilder
	for _, domain := range []string{"中文.example", "+.测试.cn"} {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
		assert.NoError(t, builder.Insert(domain))
	}
	set := builder.Build()
	assert.Equal(t, tree.NewDomainSet(), set)
	assert.NotNil(t, set)
	assert.True(t, set.Has("中文.example"))
	assert.True(t, set.Has("www.测试.cn"))
	assert.False(t, set.Has("日本語.example"))
}

func TestDomainSetOversizedKey(t *testing.T) {
	tree := trie.New[struct{}]()
	var builder trie.DomainSetBuilder
	for _, domain := range []string{"+.example.com"} {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
		assert.NoError(t, builder.Insert(domain))
	}
	set := builder.Build()
	assert.Equal(t, tree.NewDomainSet(), set)
	assert.NotNil(t, set)

	var keyBuilder strings.Builder
	for keyBuilder.Len() < 300 {
		keyBuilder.WriteString("label.")
	}
	assert.True(t, set.Has(keyBuilder.String()+"example.com"))
	assert.False(t, set.Has(keyBuilder.String()+"example.net"))
}

func BenchmarkDomainSetHas(b *testing.B) {
	var builder trie.DomainSetBuilder
	for i := 0; i < 10000; i++ {
		assert.NoError(b, builder.Insert("+."+strconv.Itoa(i)+".example.com"))
	}
	set := builder.Build()

	// Keys are split by length because the Go compiler only keeps a
	// non-constant sized allocation off the heap up to 32 bytes, so hostnames
	// longer than that used to take a different path.
	benchmarks := []struct {
		name string
		keys []string
	}{
		{"short", []string{
			"www.4242.example.com",
			"a.b.c.9999.example.com",
			"no-such-host.example.net",
			"WWW.1234.EXAMPLE.COM",
		}},
		{"long", []string{
			"ec2-52-201-13-44.compute-1.4242.example.com",
			"prod-eu-west-1-api.metrics.9999.example.com",
			"abcdef123456.dualstack.us-east-1.elb.example.net",
			"EC2-52-201-13-44.COMPUTE-1.1234.EXAMPLE.COM",
		}},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				set.Has(benchmark.keys[i%len(benchmark.keys)])
			}
		})
	}
}

func BenchmarkDomainSetBuild(b *testing.B) {
	suffixes := [...]string{
		"google.com",
		"github.io",
		"cloudflare.net",
		"mozilla.org",
		"amazonaws.com",
		"apple.com",
		"telegram.org",
		"example.co.uk",
	}
	domains := make([]string, 10000)
	for i := range domains {
		domain := strconv.Itoa(i) + "." + suffixes[i%len(suffixes)]
		switch i % 20 {
		case 0:
			domains[i] = domain
		case 1:
			domains[i] = "." + domain
		case 2:
			domains[i] = "*." + domain
		case 3:
			domains[i] = "stun.*." + domain
		default:
			domains[i] = "+." + domain
		}
		if i%50 == 49 {
			domains[i] = domains[i-1]
		}
	}

	b.Run("via_trie", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tree := trie.New[struct{}]()
			for _, domain := range domains {
				if err := tree.Insert(domain, struct{}{}); err != nil {
					b.Fatal(err)
				}
			}
			set := tree.NewDomainSet()
			runtime.KeepAlive(set)
		}
	})

	b.Run("builder", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var builder trie.DomainSetBuilder
			for _, domain := range domains {
				if err := builder.Insert(domain); err != nil {
					b.Fatal(err)
				}
			}
			set := builder.Build()
			runtime.KeepAlive(set)
		}
	})
}
