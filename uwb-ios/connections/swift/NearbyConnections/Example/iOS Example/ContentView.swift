//
//  Copyright 2023 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import SwiftUI
import NearbyConnections

struct ContentView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        NavigationSplitView {
            Form {
                TextField("peer", text: $model.endpointName)

                Toggle("advertise", isOn: $model.isAdvertisingEnabled)

                Toggle("discovery", isOn: $model.isDiscoveryEnabled)

                if !model.requests.isEmpty {
                    Section(header: Text("Pending Connections")) {
                        ForEach(model.requests) { request in
                            NavigationLink(value: request.endpointID) {
                                Text(request.endpointName)
                            }
                        }
                    }
                }

                if !model.connections.isEmpty {
                    Section(header: Text("Connections")) {
                        ForEach(model.connections) { connection in
                            NavigationLink(value: connection.endpointID) {
                                Text(connection.endpointName)
                            }
                        }
                    }
                }

                if !model.endpoints.isEmpty {
                    Section(header: Text("Endpoints")) {
                        ForEach(model.endpoints) { endpoint in
                            NavigationLink(value: endpoint.endpointID) {
                                Text(endpoint.endpointName)
                            }
                        }
                    }
                }
            }
            .navigationDestination(for: String.self) { endpointID in
                EndpointDetail(endpointID: endpointID)
            }
            .navigationTitle("ultrawideband")
        } detail: {
            Text("No Endpoints Selected")
                .font(.headline)
                .foregroundColor(.secondary)
        }
    }
}
