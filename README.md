# eBPF Contracts Hackathon

This is a simple hackathon project to demonstrate the use of eBPF as a backbone for smart-contract
execution.

The idea is similar to the sandboxing/virtualization approach we already employ. The TLDR is that
Substrate Runtime has access to API of a Wasm VM.

In this hackathon, we implement a similar virtualization API, but which is backed by eBPF VM.
