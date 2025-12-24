package kamune

import (
	"errors"
	"fmt"
	"maps"
	"sync"
)

var (
	ErrNoHandler      = errors.New("no handler registered for route")
	ErrHandlerExists  = errors.New("handler already registered for route")
	ErrRouterClosed   = errors.New("router is closed")
	ErrInvalidHandler = errors.New("handler cannot be nil")
	ErrRouteMismatch  = errors.New("received route does not match expected")
)

// RouteHandler is a function that processes a message for a specific route.
type RouteHandler func(t *Transport, msg Transferable, md *Metadata) error

// Router dispatches incoming messages to registered handlers based on their route.
type Router struct {
	handlers   map[Route]RouteHandler
	middleware []Middleware
	mu         sync.RWMutex
	closed     bool

	// Default handler for unregistered routes
	defaultHandler RouteHandler

	// Error handler for route processing errors
	errorHandler func(route Route, err error)
}

// Middleware is a function that wraps a RouteHandler to provide
// cross-cutting concerns like logging, metrics, or authentication.
type Middleware func(next RouteHandler) RouteHandler

// NewRouter creates a new message router.
func NewRouter() *Router {
	return &Router{
		handlers:   make(map[Route]RouteHandler),
		middleware: make([]Middleware, 0),
	}
}

// Handle registers a handler for a specific route.
func (r *Router) Handle(route Route, handler RouteHandler) error {
	if handler == nil {
		return ErrInvalidHandler
	}
	if !route.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidRoute, route)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrRouterClosed
	}

	if _, exists := r.handlers[route]; exists {
		return fmt.Errorf("%w: %s", ErrHandlerExists, route)
	}

	r.handlers[route] = handler
	return nil
}

// HandleFunc is a convenience method that registers a handler function.
func (r *Router) HandleFunc(route Route, handler RouteHandler) error {
	return r.Handle(route, handler)
}

// SetDefault sets the default handler for unregistered routes.
func (r *Router) SetDefault(handler RouteHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultHandler = handler
}

// SetErrorHandler sets the error handler for route processing errors.
func (r *Router) SetErrorHandler(handler func(route Route, err error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errorHandler = handler
}

// Use adds middleware to the router.
// Middleware is applied in the order it is added.
func (r *Router) Use(mw ...Middleware) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.middleware = append(r.middleware, mw...)
}

// Dispatch processes an incoming message by routing it to the appropriate handler.
func (r *Router) Dispatch(
	t *Transport, route Route, msg Transferable, md *Metadata,
) error {
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return ErrRouterClosed
	}

	handler, exists := r.handlers[route]
	if !exists {
		handler = r.defaultHandler
	}
	middleware := r.middleware
	errorHandler := r.errorHandler
	r.mu.RUnlock()

	if handler == nil {
		err := fmt.Errorf("%w: %s", ErrNoHandler, route)
		if errorHandler != nil {
			errorHandler(route, err)
		}
		return err
	}

	// Apply middleware in reverse order so they execute in registration order
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}

	err := handler(t, msg, md)
	if err != nil && errorHandler != nil {
		errorHandler(route, err)
	}
	return err
}

// DispatchNext reads the next message from the transport and dispatches it.
func (r *Router) DispatchNext(t *Transport, dst Transferable) error {
	md, route, err := t.ReceiveWithRoute(dst)
	if err != nil {
		return fmt.Errorf("receiving message: %w", err)
	}

	return r.Dispatch(t, route, dst, md)
}

// Remove removes the handler for a specific route.
func (r *Router) Remove(route Route) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.handlers[route]; exists {
		delete(r.handlers, route)
		return true
	}
	return false
}

// HasHandler returns true if a handler is registered for the route.
func (r *Router) HasHandler(route Route) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.handlers[route]
	return exists
}

// Routes returns a list of all registered routes.
func (r *Router) Routes() []Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]Route, 0, len(r.handlers))
	for route := range r.handlers {
		routes = append(routes, route)
	}
	return routes
}

// Close closes the router and prevents further dispatch operations.
func (r *Router) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.handlers = nil
}

// Clone creates a copy of the router with the same handlers and middleware.
func (r *Router) Clone() *Router {
	r.mu.RLock()
	defer r.mu.RUnlock()

	newRouter := NewRouter()
	maps.Copy(newRouter.handlers, r.handlers)
	newRouter.middleware = append(newRouter.middleware, r.middleware...)
	newRouter.defaultHandler = r.defaultHandler
	newRouter.errorHandler = r.errorHandler

	return newRouter
}

// RouteGroup allows grouping routes with shared middleware.
type RouteGroup struct {
	router     *Router
	middleware []Middleware
}

// Group creates a new route group with the specified middleware.
func (r *Router) Group(mw ...Middleware) *RouteGroup {
	return &RouteGroup{
		router:     r,
		middleware: mw,
	}
}

// Handle registers a handler for a route within the group.
func (g *RouteGroup) Handle(route Route, handler RouteHandler) error {
	// Wrap the handler with group middleware
	wrapped := handler
	for i := len(g.middleware) - 1; i >= 0; i-- {
		wrapped = g.middleware[i](wrapped)
	}
	return g.router.Handle(route, wrapped)
}

// Use adds middleware to the group.
func (g *RouteGroup) Use(mw ...Middleware) *RouteGroup {
	g.middleware = append(g.middleware, mw...)
	return g
}

// Common middleware implementations

// LoggingMiddleware logs route dispatch events.
func LoggingMiddleware(logger func(route Route, err error)) Middleware {
	return func(next RouteHandler) RouteHandler {
		return func(t *Transport, msg Transferable, md *Metadata) error {
			err := next(t, msg, md)
			if logger != nil {
				// Extract route from context if available, otherwise unknown
				logger(RouteInvalid, err)
			}
			return err
		}
	}
}

// RecoveryMiddleware recovers from panics in handlers.
func RecoveryMiddleware(onPanic func(r any)) Middleware {
	return func(next RouteHandler) RouteHandler {
		return func(t *Transport, msg Transferable, md *Metadata) (err error) {
			defer func() {
				if r := recover(); r != nil {
					if onPanic != nil {
						onPanic(r)
					}
					err = fmt.Errorf("panic in route handler: %v", r)
				}
			}()
			return next(t, msg, md)
		}
	}
}

// SessionPhaseMiddleware ensures the session is in the required phase.
func SessionPhaseMiddleware(requiredPhase SessionPhase) Middleware {
	return func(next RouteHandler) RouteHandler {
		return func(t *Transport, msg Transferable, md *Metadata) error {
			if t.Phase() < requiredPhase {
				return fmt.Errorf(
					"session phase %s does not meet required phase %s",
					t.Phase(), requiredPhase,
				)
			}
			return next(t, msg, md)
		}
	}
}

// RouteDispatcher provides a simple interface for handling route-based communication.
type RouteDispatcher struct {
	transport *Transport
	router    *Router
}

// NewRouteDispatcher creates a new route dispatcher for a transport.
func NewRouteDispatcher(t *Transport) *RouteDispatcher {
	return &RouteDispatcher{
		transport: t,
		router:    NewRouter(),
	}
}

// Router returns the underlying router.
func (rd *RouteDispatcher) Router() *Router {
	return rd.router
}

// Transport returns the underlying transport.
func (rd *RouteDispatcher) Transport() *Transport {
	return rd.transport
}

// On registers a handler for a route.
func (rd *RouteDispatcher) On(route Route, handler RouteHandler) error {
	return rd.router.Handle(route, handler)
}

// Serve starts serving incoming messages until the transport is closed.
func (rd *RouteDispatcher) Serve(msgFactory func() Transferable) error {
	for {
		msg := msgFactory()
		err := rd.router.DispatchNext(rd.transport, msg)
		if err != nil {
			if errors.Is(err, ErrConnClosed) {
				return nil
			}
			return err
		}
	}
}

// SendAndExpect sends a message and waits for a response on the expected route.
func (rd *RouteDispatcher) SendAndExpect(
	msg Transferable, sendRoute Route,
	dst Transferable, expectRoute Route,
) (*Metadata, error) {
	if _, err := rd.transport.Send(msg, sendRoute); err != nil {
		return nil, fmt.Errorf("sending: %w", err)
	}

	md, route, err := rd.transport.ReceiveWithRoute(dst)
	if err != nil {
		return nil, fmt.Errorf("receiving: %w", err)
	}

	if route != expectRoute {
		return nil, fmt.Errorf("%w: expected %s, got %s",
			ErrRouteMismatch, expectRoute, route)
	}

	return md, nil
}

// Close closes the dispatcher and its underlying transport.
func (rd *RouteDispatcher) Close() error {
	rd.router.Close()
	return rd.transport.Close()
}
