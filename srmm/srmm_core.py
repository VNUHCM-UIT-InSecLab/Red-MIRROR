import torch
from torch import nn
from transformers import GPT2Config
from transformers.models.gpt2.modeling_gpt2 import GPT2Block


class SRMMCore(nn.Module):
    """
    Minimal SRMM core implementing:
      - positional embeddings for a short sequence [agent_mem, obs_vec]
      - self-attention via GPT2Block
      - cross-attention using encoder_hidden_states argument (shared_mem)
    API:
      core = SRMMCore(hidden_size=512, num_heads=8, max_position_embeddings=1024)
      core_out, new_mem = core.forward(obs_vec, agent_mem=None, shared_mem=None)
    Shapes expected:
      obs_vec:      [B, hidden_size] or [hidden_size]  (we will unsqueeze to [B, hidden_size])
      agent_mem:    [B, hidden_size] or None
      shared_mem:   [N, hidden_size] or None  (N = total agents)
    Returns:
      core_out: [B, hidden_size]
      new_mem:  [B, hidden_size]
    """

    def __init__(self, hidden_size: int = 512, num_heads: int = 8, max_position_embeddings: int = 1024, add_cross_attention: bool = True):
        super().__init__()
        self.hidden_size = hidden_size
        self.cfg = GPT2Config(
            hidden_size=hidden_size,
            n_head=num_heads,
            n_inner=None,
            n_layer=1,  # single block is enough for minimal core; you can stack if needed
            add_cross_attention=add_cross_attention,
            n_positions=max_position_embeddings,
            n_ctx=max_position_embeddings,
        )
        # single transformer block
        self.transformer_block = GPT2Block(self.cfg)
        # small projection layer to ensure obs/agent_mem fit hidden_size
        self.proj_in = nn.Linear(hidden_size, hidden_size) if False else None
        self.wpe = nn.Embedding(max_position_embeddings, hidden_size)
        self.ln_f = nn.LayerNorm(hidden_size, eps=1e-5)
        # mem head to map transformer output to memory embedding space
        self.mem_head = nn.Linear(hidden_size, hidden_size, bias=False)

    def forward(self, obs_vec, agent_mem=None, shared_mem=None):
        """
        obs_vec: Tensor [B, hidden_size] or [hidden_size]
        agent_mem: Tensor [B, hidden_size] or None
        shared_mem: Tensor [N, hidden_size] or None
        """
        # ensure 2D batch dimension
        if obs_vec.dim() == 1:
            obs = obs_vec.unsqueeze(0)  # [1, d]
        else:
            obs = obs_vec  # [B, d]
        B = obs.size(0)

        device = obs.device

        # prepare agent memory
        if agent_mem is None:
            agent_mem = torch.zeros(B, self.hidden_size, device=device)
        else:
            # if agent_mem shape is [1, d] and B>1, expand
            if agent_mem.size(0) == 1 and B > 1:
                agent_mem = agent_mem.expand(B, -1).contiguous()

        # optional projection (disabled by default)
        if self.proj_in is not None:
            obs = self.proj_in(obs)

        # Build inputs sequence: [agent_mem, obs] -> sequence length = 2
        seq = torch.stack([agent_mem, obs], dim=1)  # [B, 2, d]

        # positional ids for seq positions (0,1)
        pos_ids = torch.arange(0, seq.size(1), dtype=torch.long, device=device).unsqueeze(0)  # [1, seq_len]
        pos_emb = self.wpe(pos_ids).expand(B, -1, -1)  # [B, seq_len, d]

        hidden_states = seq + pos_emb  # [B, seq_len, d]

        # encoder_hidden_states (shared memory) must be shape [B, enc_seq_len, d]
        encoder_hidden_states = None
        if shared_mem is not None:
            # shared_mem may be [N, d] or [1, N, d]; convert to [B, N, d]
            if shared_mem.dim() == 2:
                enc = shared_mem.unsqueeze(0).expand(B, -1, -1).contiguous()
            elif shared_mem.dim() == 3:
                enc = shared_mem.expand(B, -1, -1).contiguous()
            else:
                raise ValueError("shared_mem must be 2D or 3D tensor")
            encoder_hidden_states = enc  # [B, N, d]

        # GPT2Block forward expects hidden_states [B, seq_len, d]
        # and optionally encoder_hidden_states for cross-attention
        # It returns a tuple (hidden_states, present)
        transformer_out = self.transformer_block(
            hidden_states=hidden_states.contiguous(),
            encoder_hidden_states=encoder_hidden_states
        )[0]  # [B, seq_len, d]

        transformer_out = self.ln_f(transformer_out)  # layer norm
        # core output = last token (obs position)
        core_out = transformer_out[:, -1, :].contiguous()  # [B, d]

        # new memory: map transformer output to mem space
        new_mem = self.mem_head(core_out)  # [B, d]

        return core_out, new_mem
