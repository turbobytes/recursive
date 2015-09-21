package recursive

import (
	//	"errors"
	"fmt"
	"github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"sort"
	"time"
)

type cachekey struct {
	question dns.Question
	server   string
}

type Resolver struct {
	cache     *lru.Cache
	Roothints []string
	Debug     bool
}

func NewResolver() *Resolver {
	r := &Resolver{}
	r.cache, _ = lru.New(10000)
	r.Roothints = []string{"198.41.0.4",
		"192.228.79.201",
		"192.33.4.12",
		"199.7.91.13",
		"192.203.230.10",
		"192.5.5.241",
		"192.112.36.4",
		"128.63.2.53",
		"192.36.148.17",
		"192.58.128.30",
		"193.0.14.129",
		"199.7.83.42",
		"202.12.27.33",
	}
	return r
}

func (r *Resolver) Resolve(msg *dns.Msg) error {
	if r.Debug {
		log.Println(msg.Question)
	}
	_, err := r.resolve(msg.Question[0], msg, r.Roothints, r.Roothints, 0)
	if r.Debug {
		//log.Println(msg)
		if err != nil {
			log.Println(err)
		}
	}
	return err
}

func shuffle(arr []string) {
	t := time.Now()
	rand.Seed(int64(t.Nanosecond())) // no shuffling without this line

	for i := len(arr) - 1; i > 0; i-- {
		j := rand.Intn(i)
		arr[i], arr[j] = arr[j], arr[i]
	}
}

func (r *Resolver) resolve(question dns.Question, result *dns.Msg, servers, original []string, loopcount int) ([]dns.RR, error) {
	if len(servers) == 0 {
		if r.Debug {
			log.Println("No more servers to query...")
		}
		result.Rcode = dns.RcodeServerFailure
		return nil, nil
	}
	//infinite loop prevention
	if loopcount == 30 {
		if r.Debug {
			log.Println("Loop count exhausted")
		}
		result.Rcode = dns.RcodeServerFailure
		return nil, nil
	}
	loopcount++
	//Pick a server randomly
	shuffle(servers)
	server := servers[0] + ":53"
	nservers := []string{}
	for i, s := range servers {
		if i != 0 {
			nservers = append(nservers, s)
		}
	}
	if r.Debug {
		log.Println(server)
		log.Println(nservers)
	}
	m := &dns.Msg{}
	m.SetQuestion(question.Name, question.Qtype)
	m.RecursionDesired = false
	res, err := r.exchange(m, server, original)
	if r.Debug {
		if err != nil {
			log.Println(res, err)
		}
	}
	if err != nil {
		if r.Debug {
			log.Println(err)
		}
		//Restart with remaining servers
		return r.resolve(question, result, nservers, original, loopcount)
	}
	//Check status...
	if res.Rcode != dns.RcodeSuccess {
		//Restart with remaining servers
		return r.resolve(question, result, nservers, original, loopcount)
	}
	answerfound := false
	var cname dns.Question
	//Check for answers
	for _, ans := range res.Answer {
		result.Answer = append(result.Answer, ans)
		if ans.Header().Rrtype == question.Qtype {
			answerfound = true
		}
		if ans.Header().Rrtype == dns.TypeCNAME {
			c, _ := ans.(*dns.CNAME)
			cname.Name = c.Target
			cname.Qtype = question.Qtype
		}
	}
	if answerfound {
		return nil, nil
	}
	if cname.Name != "" {
		if r.Debug {
			log.Println("CNAME", cname, cname.Name)
		}
		return r.resolve(cname, result, r.Roothints, r.Roothints, loopcount)
	}
	//OK no ans of target type.... or CNAME found... process NS...
	ns := make(map[string]string)
	for _, n := range res.Ns {
		nsrec, _ := n.(*dns.NS)
		if nsrec != nil {
			ns[nsrec.Ns] = ""
		}
	}
	//Try to populate ips from additional...
	for _, a := range res.Extra {
		extra, ok := a.(*dns.A)
		if ok {
			_, ok := ns[extra.Header().Name]
			if ok {
				ns[extra.Header().Name] = extra.A.String()
			}
		}
	}
	newservers := []string{}
	//Fill in the missing ips
	for k, ip := range ns {
		if ip == "" {
			nsmsg := &dns.Msg{}
			nsmsg.SetQuestion(k, dns.TypeA)
			//Lets cheat and ask a recursive...
			nsmsg.RecursionDesired = true
			nsres, err := r.exchange(nsmsg, "8.8.8.8:53", []string{"8.8.8.8"})
			if err == nil {
				for _, ans := range nsres.Answer {
					arec, ok := ans.(*dns.A)
					if ok {
						newservers = append(newservers, arec.A.String())
					}
				}
			}
		} else {
			newservers = append(newservers, ip)
		}
	}

	if r.Debug {
		log.Println(ns)
		log.Println(newservers)
	}
	if len(newservers) == 0 {
		//Restart
		return r.resolve(question, result, nservers, original, loopcount)
		//return nil, errors.New("No NS record")
	}
	return r.resolve(question, result, newservers, newservers, 0)
	return nil, nil
}

func (r *Resolver) exchange(m *dns.Msg, a string, original []string) (res *dns.Msg, err error) {
	question := m.Question[0]
	sort.Strings(original)
	key := cachekey{question, fmt.Sprintf("%v", original)}
	if r.Debug {
		log.Println("KEY: ", key)
	}
	rt, ok := r.cache.Get(key)
	if ok {
		if r.Debug {
			log.Println("Cache HIT")
		}
		r1 := rt.(*dns.Msg)
		res = r1.Copy()
		return
	}
	if r.Debug {
		log.Println("Cache MISS")
		log.Println("QUERY: ", question.Name, "via", a)
	}
	res, err = dns.Exchange(m, a)
	if err != nil {
		if r.Debug {
			log.Println(err)
		}
		return
	}
	//Retry in case it was truncated
	if res.Truncated {
		if r.Debug {
			log.Println("truncated, retrying with tcp")
		}

		cl := new(dns.Client)
		cl.Net = "tcp"
		res, _, err = cl.Exchange(m, a)
		if err != nil {
			if r.Debug {
				log.Println(err)
			}
			return
		}

	}

	if r.Debug {
		log.Println(res)
	}
	if res.Rcode != dns.RcodeSuccess {
		return
	}
	if r.Debug {
		log.Println("Inserting into cache")
	}
	r.cache.Add(key, res)
	return
}
