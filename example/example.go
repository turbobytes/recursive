package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/turbobytes/recursive"
	"os"
)

func main() {
	r := recursive.NewResolver()
	r.Debug = true
	query := &dns.Msg{}
	query.SetQuestion(os.Args[1], dns.TypeA)
	r.Resolve(query)
	fmt.Println("=============== Result ================")
	fmt.Println(query)
}
