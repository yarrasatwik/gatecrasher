package ai

import "github.com/yarrasatwik/gatecrasher/internal/httpx"

func requestTo(u string) httpx.Request { return httpx.Request{URL: u} }
