/* Audio worklet: mixes input channels to mono and hands the page 4096-sample
 * blocks, so chunking for speech-to-text stays on the main thread. */
class RukoTap extends AudioWorkletProcessor {
  constructor() {
    super();
    this.buf = new Float32Array(4096);
    this.n = 0;
  }

  process(inputs) {
    const input = inputs[0];
    if (input && input.length) {
      const len = input[0].length;
      for (let i = 0; i < len; i++) {
        let s = 0;
        for (let c = 0; c < input.length; c++) s += input[c][i];
        this.buf[this.n++] = s / input.length;
        if (this.n === this.buf.length) {
          this.port.postMessage(this.buf.slice(0));
          this.n = 0;
        }
      }
    }
    return true;
  }
}

registerProcessor('ruko-tap', RukoTap);
