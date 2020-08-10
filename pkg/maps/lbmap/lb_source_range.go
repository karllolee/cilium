// Copyright 2020 Authors of Cilium
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

package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
)

const (
	SourceRange4MapName = "cilium_lb4_source_range"
	lpmPrefixLenV4      = 16 + 16 // sizeof(RevNATID) + sizeof(Pad)
)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SourceRangeKey4 struct {
	PrefixLen uint32     `align:"lpm"`
	RevNATID  uint16     `align:"rev_nat_id"`
	Pad       uint16     `align:"pad"`
	Address   types.IPv4 `align:"addr"`
}

func (k *SourceRangeKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *SourceRangeKey4) NewValue() bpf.MapValue    { return &SourceRangeValue{} }
func (k *SourceRangeKey4) String() string            { return fmt.Sprintf("%s", k.Address) }
func (k *SourceRangeKey4) ToNetwork() *SourceRangeKey4 {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNATID = byteorder.HostToNetwork(n.RevNATID).(uint16)
	return &n
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type SourceRangeValue struct {
	Pad uint8 // not used
}

func (v *SourceRangeValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SourceRangeValue) String() string              { return "" }

var SourceRange4Map = bpf.NewMap(
	SourceRange4MapName,
	bpf.MapTypeLPMTrie,
	&SourceRangeKey4{}, int(unsafe.Sizeof(SourceRangeKey4{})),
	&SourceRangeValue{}, int(unsafe.Sizeof(SourceRangeValue{})),
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	func(key []byte, value []byte, mapKey bpf.MapKey, mapValue bpf.MapValue) (bpf.MapKey, bpf.MapValue, error) {
		sKey, sVal := mapKey.(*SourceRangeKey4), mapValue.(*SourceRangeValue)

		if _, _, err := bpf.ConvertKeyValue(key, value, sKey, sVal); err != nil {
			return nil, nil, err
		}

		return sKey.ToNetwork(), sVal, nil
	},
).WithCache()

//func Update(cidr net.IPNet, revNATID uint16) error {
//	return SourceRange4Map.Update(srcKey4(cidr, revNATID), &SourceRangeValue{})
//}
//
//func  Delete(cidr net.IPNet, revNATID uint16) error {
//	return SourceRange4Map.Delete(srcKey4(cidr, revNATID))
//}

func srcKey4(cidr *net.IPNet, revNATID uint16) *SourceRangeKey4 {
	ones, _ := cidr.Mask.Size()
	id := byteorder.HostToNetwork(revNATID).(uint16)
	key := &SourceRangeKey4{PrefixLen: uint32(ones) + lpmPrefixLenV4, RevNATID: id}
	copy(key.Address[:], cidr.IP.To4())
	return key
}

func srcKey4ToIPNet(key *SourceRangeKey4) *net.IPNet {
	var (
		cidr net.IPNet
		ip   types.IPv4
	)

	cidr.Mask = net.CIDRMask(int(key.PrefixLen)-lpmPrefixLenV4, 32)
	key.Address.DeepCopyInto(&ip)
	cidr.IP = ip.IP()

	return &cidr
}
