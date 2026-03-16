package scanner

import (
	"sync"
	"testing"
	"time"
)

func TestCrawlQueueSaturationDoesNotHang(t *testing.T) {
	done := make(chan struct{})

	go func() {
		defer close(done)

		queue := make(chan CrawlJob, 1)
		var wg sync.WaitGroup

		if !enqueueCrawlJob(queue, CrawlJob{URL: "https://example.com/a", Depth: 1}, &wg) {
			t.Error("expected first enqueue to succeed")
			return
		}
		if enqueueCrawlJob(queue, CrawlJob{URL: "https://example.com/b", Depth: 1}, &wg) {
			t.Error("expected second enqueue to fail when queue is saturated")
			return
		}

		<-queue
		wg.Done()
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scanner queue handling appears to hang")
	}
}
