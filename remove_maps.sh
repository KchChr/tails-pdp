#!/usr/bin/env bash
#
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/SOCKET_BIND_STATIC_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/SOCKET_BIND_STREAM_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/STATIC_POLICY
sudo rm -f /sys/fs/bpf/tails-pdp/STREAM_POLICY
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME_ISO8601
sudo rm -f /sys/fs/bpf/tails-pdp/ATTRIBUTES
sudo rm -f /sys/fs/bpf/tails-pdp/ATTRIBUTE_GENERATION
sudo rm -f /sys/fs/bpf/tails-pdp/POLICY_GENERATION
