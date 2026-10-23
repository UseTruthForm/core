// Package schedule runs work along a dependency graph, many at once: each
// item starts as soon as everything it depends on has finished. A restore
// is wide and shallow (a VPC, then its subnets and groups; a queue, then
// the queue that dead-letters into it), so run one at a time it waited
// mostly on things that did not concern it: 4m33s for 17 AWS resources in
// the real drill, of which the longest chain is about two minutes.
package schedule

// Run calls do for every item 0..n-1, at most workers at once, starting an
// item only when all of deps[i] have finished. deps must hold no cycle
// (callers set cyclic items aside first); an item whose dependency failed
// still runs, and says so itself. Items become ready in index order, so
// with one worker the run is the sequential one.
func Run(n int, deps [][]int, workers int, do func(i int)) {
	if workers < 1 {
		workers = 1
	}
	waiting := make([]int, n)
	dependents := make([][]int, n)
	for i := 0; i < n; i++ {
		for _, d := range deps[i] {
			if d == i {
				continue
			}
			waiting[i]++
			dependents[d] = append(dependents[d], i)
		}
	}
	var ready []int
	for i := 0; i < n; i++ {
		if waiting[i] == 0 {
			ready = append(ready, i)
		}
	}
	fin := make(chan int)
	running, finished := 0, 0
	for finished < n {
		for running < workers && len(ready) > 0 {
			i := ready[0]
			ready = ready[1:]
			running++
			go func() {
				do(i)
				fin <- i
			}()
		}
		if running == 0 {
			// Nothing running and nothing ready: the rest wait on a cycle
			// the caller did not set aside. Refuse to hang.
			panic("schedule: dependency cycle among the remaining items")
		}
		i := <-fin
		running--
		finished++
		for _, d := range dependents[i] {
			if waiting[d]--; waiting[d] == 0 {
				ready = insertSorted(ready, d)
			}
		}
	}
}

func insertSorted(s []int, v int) []int {
	i := len(s)
	for i > 0 && s[i-1] > v {
		i--
	}
	s = append(s, 0)
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
}
