// Copyright 2025 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package watcher

import "sync"

// Callback is the signature of the callbacks.
type Callback func(Data)

// Data holds the data from the watcher.
type Data struct {
	Value interface{}
	Err   error
}

// Watcher defines the interface that a watcher must implement.
type Watcher interface {
	// Watch is called to register callbacks to be notified when a watched named changes.
	Watch(string, ...Callback) error
	// Start is called to initiate the watches and provide a channel to signal when to stop watching.
	Start(<-chan struct{}) error
	// OnError is called when an error occurs.
	OnError(string, error)
	// OnChange is called when a change is detected.
	OnChange(interface{})
}

// WithCallbacks binds callbacks to a watcher instance.
type WithCallbacks struct {
	sync.RWMutex
	Callbacks map[string][]Callback
}

// Watch initializes watcher.
func (w *WithCallbacks) Watch(name string, callbacks ...Callback) error {
	w.Lock()
	defer w.Unlock()
	if w.Callbacks == nil {
		w.Callbacks = make(map[string][]Callback, 1)
	}
	w.Callbacks[name] = append(w.Callbacks[name], callbacks...)
	return nil
}

// OnError is called when an error occurs.
func (w *WithCallbacks) OnError(name string, err error) {
	w.RLock()
	defer w.RUnlock()
	// Iterate over the callbacks and invoke their callbacks.
	for _, callback := range w.Callbacks[name] {
		callback(Data{Value: nil, Err: err})
	}
}
