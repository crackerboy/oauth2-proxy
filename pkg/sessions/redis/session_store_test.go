package redis

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/Bose/minisentinel"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v7"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/tests"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSessionStore(t *testing.T) {
	logger.SetOutput(GinkgoWriter)

	redisLogger := log.New(os.Stderr, "redis: ", log.LstdFlags|log.Lshortfile)
	redisLogger.SetOutput(GinkgoWriter)
	redis.SetLogger(redisLogger)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Redis SessionStore")
}

var _ = Describe("Redis SessionStore Tests", func() {
	var mr *miniredis.Miniredis

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		mr.Close()
	})

	tests.RunSessionStoreTests(
		func(opts *options.SessionOptions, cookieOpts *options.CookieOptions) (sessionsapi.SessionStore, error) {
			// Set the connection URL
			opts.Type = options.RedisSessionStoreType
			opts.Redis.ConnectionURL = "redis://" + mr.Addr()
			return NewRedisSessionStore(opts, cookieOpts)
		},
		func(d time.Duration) error {
			mr.FastForward(d)
			return nil
		},
	)

	Context("with sentinel", func() {
		var ms *minisentinel.Sentinel

		BeforeEach(func() {
			ms = minisentinel.NewSentinel(mr)
			Expect(ms.Start()).To(Succeed())
		})

		AfterEach(func() {
			ms.Close()
		})

		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.CookieOptions) (sessionsapi.SessionStore, error) {
				// Set the sentinel connection URL
				sentinelAddr := "redis://" + ms.Addr()
				opts.Type = options.RedisSessionStoreType
				opts.Redis.SentinelConnectionURLs = []string{sentinelAddr}
				opts.Redis.UseSentinel = true
				opts.Redis.SentinelMasterName = ms.MasterInfo().Name
				return NewRedisSessionStore(opts, cookieOpts)
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)
	})
})
