// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package middleware

import (
	"net/http"
	"strings"

	"github.com/go-swagger/go-swagger/errors"
	"github.com/go-swagger/go-swagger/httpkit"
	"github.com/go-swagger/go-swagger/httpkit/middleware/untyped"
	"github.com/go-swagger/go-swagger/spec"
	"github.com/go-swagger/go-swagger/strfmt"
	"github.com/go-swagger/go-swagger/swag"
	// "github.com/gorilla/context"
	"golang.org/x/net/context"
)

// A Builder can create middlewares
type Builder func(http.Handler) http.Handler

// PassthroughBuilder returns the handler, aka the builder identity function
func PassthroughBuilder(handler http.Handler) http.Handler { return handler }

// RequestBinder is an interface for types to implement
// when they want to be able to bind from a request
type RequestBinder interface {
	BindRequest(*http.Request, *MatchedRoute) error
}

// Responder is an interface for types to implement
// when they want to be considered for writing HTTP responses
type Responder interface {
	WriteResponse(http.ResponseWriter, httpkit.Producer)
}

// ResponderFunc wraps a func as a Responder interface
type ResponderFunc func(http.ResponseWriter, httpkit.Producer)

// WriteResponse writes to the response
func (fn ResponderFunc) WriteResponse(rw http.ResponseWriter, pr httpkit.Producer) {
	fn(rw, pr)
}

// Context is a type safe wrapper around an untyped request context
// used throughout to store request context with the gorilla context module
type Context struct {
	spec        *spec.Document
	api         RoutableAPI
	router      Router
	formats     strfmt.Registry
	rootContext context.Context
}

type routableUntypedAPI struct {
	api             *untyped.API
	handlers        map[string]map[string]http.Handler
	defaultConsumes string
	defaultProduces string
}

func newRoutableUntypedAPI(spec *spec.Document, api *untyped.API, ctx *Context) *routableUntypedAPI {
	var handlers map[string]map[string]http.Handler
	if spec == nil || api == nil {
		return nil
	}
	for method, hls := range spec.Operations() {
		um := strings.ToUpper(method)
		for path, op := range hls {
			schemes := spec.SecurityDefinitionsFor(op)

			if oh, ok := api.OperationHandlerFor(method, path); ok {
				if handlers == nil {
					handlers = make(map[string]map[string]http.Handler)
				}
				if b, ok := handlers[um]; !ok || b == nil {
					handlers[um] = make(map[string]http.Handler)
				}

				handlers[um][path] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					swres := w.(*swresponse)
					// lookup route info in the ctx
					route, ct, _ := ctx.RouteInfo(swres.context, r)

					// bind and validate the request using reflection
					bound, bct, validation := ctx.BindAndValidate(ct, r, route)
					if validation != nil {
						ctx.Respond(bct, w, r, route.Produces, route, validation)
						return
					}

					// actually handle the request
					result, err := oh.Handle(bound)
					if err != nil {
						// respond with failure
						ctx.Respond(bct, w, r, route.Produces, route, err)
						return
					}

					// respond with success
					ctx.Respond(bct, w, r, route.Produces, route, result)
				})

				if len(schemes) > 0 {
					handlers[um][path] = newSecureAPI(ctx, handlers[um][path])
				}
			}
		}
	}

	return &routableUntypedAPI{
		api:             api,
		handlers:        handlers,
		defaultProduces: api.DefaultProduces,
		defaultConsumes: api.DefaultConsumes,
	}
}

func (r *routableUntypedAPI) HandlerFor(method, path string) (http.Handler, bool) {
	paths, ok := r.handlers[strings.ToUpper(method)]
	if !ok {
		return nil, false
	}
	handler, ok := paths[path]
	return handler, ok
}
func (r *routableUntypedAPI) ServeErrorFor(operationID string) func(http.ResponseWriter, *http.Request, error) {
	return r.api.ServeError
}
func (r *routableUntypedAPI) ConsumersFor(mediaTypes []string) map[string]httpkit.Consumer {
	return r.api.ConsumersFor(mediaTypes)
}
func (r *routableUntypedAPI) ProducersFor(mediaTypes []string) map[string]httpkit.Producer {
	return r.api.ProducersFor(mediaTypes)
}
func (r *routableUntypedAPI) AuthenticatorsFor(schemes map[string]spec.SecurityScheme) map[string]httpkit.Authenticator {
	return r.api.AuthenticatorsFor(schemes)
}
func (r *routableUntypedAPI) Formats() strfmt.Registry {
	return r.api.Formats()
}

func (r *routableUntypedAPI) DefaultProduces() string {
	return r.defaultProduces
}

func (r *routableUntypedAPI) DefaultConsumes() string {
	return r.defaultConsumes
}

// NewRoutableContext creates a new context for a routable API
func NewRoutableContext(spec *spec.Document, routableAPI RoutableAPI, routes Router) *Context {
	ctx := &Context{spec: spec, api: routableAPI, rootContext: context.TODO()}
	return ctx
}

// NewContext creates a new context wrapper
func NewContext(spec *spec.Document, api *untyped.API, routes Router) *Context {
	ctx := &Context{spec: spec, rootContext: context.TODO()}
	ctx.api = newRoutableUntypedAPI(spec, api, ctx)
	return ctx
}

// Serve serves the specified spec with the specified api registrations as a http.Handler
func Serve(spec *spec.Document, api *untyped.API) http.Handler {
	return ServeWithBuilder(spec, api, PassthroughBuilder)
}

// ServeWithBuilder serves the specified spec with the specified api registrations as a http.Handler that is decorated
// by the Builder
func ServeWithBuilder(spec *spec.Document, api *untyped.API, builder Builder) http.Handler {
	context := NewContext(spec, api, nil)
	return context.APIHandler(builder)
}

type contextKey int8

const (
	_ contextKey = iota
	ctxContentType
	ctxResponseFormat
	ctxMatchedRoute
	ctxAllowedMethods
	ctxBoundParams
	ctxSecurityPrincipal

	ctxConsumer
)

type contentTypeValue struct {
	MediaType string
	Charset   string
}

// BasePath returns the base path for this API
func (c *Context) BasePath() string {
	return c.spec.BasePath()
}

// RequiredProduces returns the accepted content types for responses
func (c *Context) RequiredProduces() []string {
	return c.spec.RequiredProduces()
}

// Context returns the golang.org/net/context.Context for this request
func (c *Context) Context(rw http.ResponseWriter) context.Context {
	if v, ok := rw.(Contexter); ok {
		return v.Context()
	}
	return c.rootContext
}

// BindValidRequest binds a params object to a request but only when the request is valid
// if the request is not valid an error will be returned
func (c *Context) BindValidRequest(context context.Context, request *http.Request, route *MatchedRoute, binder RequestBinder) error {
	var res []error

	requestContentType := "*/*"
	// check and validate content type, select consumer
	if httpkit.CanHaveBody(request.Method) {
		ct, _, err := httpkit.ContentType(request.Header, httpkit.IsDelete(request.Method))
		if err != nil {
			res = append(res, err)
		} else {
			if err := validateContentType(route.Consumes, ct); err != nil {
				res = append(res, err)
			}
			route.Consumer = route.Consumers[ct]
			requestContentType = ct
		}
	}

	// check and validate the response format
	if len(res) == 0 && httpkit.NeedsContentType(request.Method) {
		if str := NegotiateContentType(request, route.Produces, requestContentType); str == "" {
			res = append(res, errors.InvalidResponseFormat(request.Header.Get(httpkit.HeaderAccept), route.Produces))
		}
	}

	// now bind the request with the provided binder
	// it's assumed the binder will also validate the request and return an error if the
	// request is invalid
	if binder != nil && len(res) == 0 {
		if err := binder.BindRequest(request, route); err != nil {
			res = append(res, err)
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (c *Context) contentType(ctx context.Context) *contentTypeValue {
	return ctx.Value(ctxContentType).(*contentTypeValue)
}

func (c *Context) setContentType(ctx context.Context, value *contentTypeValue) context.Context {
	return context.WithValue(ctx, ctxContentType, value)
}

// ContentType gets the parsed value of a content type
func (c *Context) ContentType(context context.Context, request *http.Request) (string, string, context.Context, *errors.ParseError) {
	if val := c.contentType(context); val != nil {
		return val.MediaType, val.Charset, context, nil
	}

	mt, cs, err := httpkit.ContentType(request.Header, httpkit.IsDelete(request.Method))
	if err != nil {
		return "", "", context, err
	}
	return mt, cs, c.setContentType(context, &contentTypeValue{mt, cs}), nil
}

// LookupRoute looks a route up and returns true when it is found
func (c *Context) LookupRoute(request *http.Request) (*MatchedRoute, bool) {
	if route, ok := c.router.Lookup(request.Method, request.URL.Path); ok {
		return route, ok
	}
	return nil, false
}

func (c *Context) routeInfo(ctx context.Context) *MatchedRoute {
	return ctx.Value(ctxMatchedRoute).(*MatchedRoute)
}

func (c *Context) setRouteInfo(ctx context.Context, route *MatchedRoute) context.Context {
	return context.WithValue(ctx, ctxMatchedRoute, route)
}

// RouteInfo tries to match a route for this request
func (c *Context) RouteInfo(context context.Context, request *http.Request) (*MatchedRoute, context.Context, bool) {
	if val := c.routeInfo(context); val != nil {
		return val, context, true
	}

	if route, ok := c.LookupRoute(request); ok {
		return route, c.setRouteInfo(context, route), ok
	}

	return nil, context, false
}

func (c *Context) responseFormat(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxResponseFormat).(string)
	return v, ok
}

func (c *Context) setResponseFormat(ctx context.Context, rf string) context.Context {
	return context.WithValue(ctx, ctxResponseFormat, rf)
}

// ResponseFormat negotiates the response content type
func (c *Context) ResponseFormat(context context.Context, r *http.Request, offers []string) (string, context.Context) {
	if val, ok := c.responseFormat(context); ok {
		return val, context
	}

	format := NegotiateContentType(r, offers, "")
	return format, c.setResponseFormat(context, format)
}

// AllowedMethods gets the allowed methods for the path of this request
func (c *Context) AllowedMethods(request *http.Request) []string {
	return c.router.OtherMethods(request.Method, request.URL.Path)
}

func (c *Context) securityPrincipal(ctx context.Context) interface{} {
	return ctx.Value(ctxSecurityPrincipal)
}

func (c *Context) setSecurityPrincipal(ctx context.Context, value interface{}) context.Context {
	return context.WithValue(ctx, ctxSecurityPrincipal, value)
}

// Authorize authorizes the request
func (c *Context) Authorize(context context.Context, request *http.Request, route *MatchedRoute) (interface{}, context.Context, error) {
	if len(route.Authenticators) == 0 {
		return nil, context, nil
	}

	if v := c.securityPrincipal(context); v != nil {
		return v, context, nil
	}

	for _, authenticator := range route.Authenticators {
		applies, usr, err := authenticator.Authenticate(request)
		if !applies || err != nil || usr == nil {
			continue
		}
		return usr, c.setSecurityPrincipal(context, usr), nil
	}

	return nil, context, errors.Unauthenticated("invalid credentials")
}

func (c *Context) boundParams(ctx context.Context) (*validation, bool) {
	v, ok := ctx.Value(ctxBoundParams).(*validation)
	return v, ok && !swag.IsZero(v)
}

func (c *Context) setBoundParams(ctx context.Context, value *validation) context.Context {
	return context.WithValue(ctx, ctxBoundParams, value)
}

// BindAndValidate binds and validates the request
func (c *Context) BindAndValidate(context context.Context, request *http.Request, matched *MatchedRoute) (interface{}, context.Context, error) {
	if val, ok := c.boundParams(context); ok {
		if len(val.result) > 0 {
			return nil, context, errors.CompositeValidationError(val.result...)
		}
		return val.bound, context, nil
	}

	result := validateRequest(c, request, matched)
	nctx := c.setBoundParams(context, result)
	if len(result.result) > 0 {
		return nil, nctx, errors.CompositeValidationError(result.result...)
	}
	return result.bound, nctx, nil
}

// NotFound the default not found responder for when no route has been matched yet
func (c *Context) NotFound(ctx context.Context, rw http.ResponseWriter, r *http.Request) {
	c.Respond(ctx, rw, r, []string{c.api.DefaultProduces()}, nil, errors.NotFound("not found"))
}

// Respond renders the response after doing some content negotiation
func (c *Context) Respond(context context.Context, rw http.ResponseWriter, r *http.Request, produces []string, route *MatchedRoute, data interface{}) {
	offers := []string{c.api.DefaultProduces()}
	for _, mt := range produces {
		if mt != c.api.DefaultProduces() {
			offers = append(offers, mt)
		}
	}

	format, _ := c.ResponseFormat(context, r, offers)
	rw.Header().Set(httpkit.HeaderContentType, format)

	if resp, ok := data.(Responder); ok {
		producers := route.Producers
		prod, ok := producers[format]
		if !ok {
			prods := c.api.ProducersFor([]string{c.api.DefaultProduces()})
			pr, ok := prods[c.api.DefaultProduces()]
			if !ok {
				panic(errors.New(http.StatusInternalServerError, "can't find a producer for "+format))
			}
			prod = pr
		}
		resp.WriteResponse(rw, prod)
		return
	}

	if err, ok := data.(error); ok {
		if format == "" {
			rw.Header().Set(httpkit.HeaderContentType, httpkit.JSONMime)
		}
		if route == nil || route.Operation == nil {
			c.api.ServeErrorFor("")(rw, r, err)
			return
		}
		c.api.ServeErrorFor(route.Operation.ID)(rw, r, err)
		return
	}

	if route == nil || route.Operation == nil {
		rw.WriteHeader(200)
		if r.Method == "HEAD" {
			return
		}
		producers := c.api.ProducersFor(offers)
		prod, ok := producers[format]
		if !ok {
			panic(errors.New(http.StatusInternalServerError, "can't find a producer for "+format))
		}
		if err := prod.Produce(rw, data); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
		return
	}

	if _, code, ok := route.Operation.SuccessResponse(); ok {
		rw.WriteHeader(code)
		if code == 204 || r.Method == "HEAD" {
			return
		}

		producers := route.Producers
		prod, ok := producers[format]
		if !ok {
			if !ok {
				prods := c.api.ProducersFor([]string{c.api.DefaultProduces()})
				pr, ok := prods[c.api.DefaultProduces()]
				if !ok {
					panic(errors.New(http.StatusInternalServerError, "can't find a producer for "+format))
				}
				prod = pr
			}
		}
		if err := prod.Produce(rw, data); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
		return
	}

	c.api.ServeErrorFor(route.Operation.ID)(rw, r, errors.New(http.StatusInternalServerError, "can't produce response"))
}

// APIHandler returns a handler to serve
func (c *Context) APIHandler(builder Builder) http.Handler {
	b := builder
	if b == nil {
		b = PassthroughBuilder
	}
	return specMiddleware(c, newRouter(c, b(newOperationExecutor(c))))
}
