// SPDX-License-Identifier: AGPL-3.0-only

//go:build js && wasm

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"syscall/js"
)

// bridge reicht Anfragen des Service Workers an den echten Handler.
//
//	fn(method, url, headers: [string, string][], body: Uint8Array | null)
//	  → Promise<{status, headers: [string, string][], body: Uint8Array}>
type bridge struct {
	h  http.Handler
	fn js.Func
}

func newBridge(h http.Handler) *bridge {
	b := &bridge{h: h}
	b.fn = js.FuncOf(b.call)
	return b
}

func (b *bridge) call(this js.Value, args []js.Value) any {
	method, target, hdrs, body := args[0].String(), args[1].String(), args[2], args[3]
	var raw []byte
	if body.Truthy() {
		raw = make([]byte, body.Length())
		js.CopyBytesToGo(raw, body)
	}
	var handler js.Func
	handler = js.FuncOf(func(this js.Value, pargs []js.Value) any {
		resolve, reject := pargs[0], pargs[1]
		go func() {
			defer handler.Release()
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(js.Global().Get("Error").New("Server: Absturz"))
				}
			}()
			req, err := http.NewRequest(method, target, bytes.NewReader(raw))
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			for i := 0; i < hdrs.Length(); i++ {
				kv := hdrs.Index(i)
				req.Header.Add(kv.Index(0).String(), kv.Index(1).String())
			}
			req.RemoteAddr = "127.0.0.1:1"
			req.RequestURI = req.URL.RequestURI()
			req.ContentLength = int64(len(raw))
			rec := httptest.NewRecorder()
			b.h.ServeHTTP(rec, req)
			res := rec.Result()
			out := js.Global().Get("Array").New()
			for k, vs := range res.Header {
				for _, v := range vs {
					out.Call("push", js.Global().Get("Array").New(k, v))
				}
			}
			data := rec.Body.Bytes()
			arr := js.Global().Get("Uint8Array").New(len(data))
			js.CopyBytesToJS(arr, data)
			obj := js.Global().Get("Object").New()
			obj.Set("status", res.StatusCode)
			obj.Set("headers", out)
			obj.Set("body", arr)
			resolve.Invoke(obj)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}
