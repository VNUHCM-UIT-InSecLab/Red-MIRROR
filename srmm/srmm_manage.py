# srmm/srmm_manage.py
import torch
from typing import Dict, Any, List

class SRMMManager:
    def __init__(self, core_model=None, num_agents=3, text_mode=False):
        self.text_mode = text_mode
        if not text_mode:
            self.core = core_model
            self.memories = {
                f"agent_{i}": torch.zeros(1, getattr(self.core, "hidden_size", 512))
                for i in range(num_agents)
            }
        else:
            # text mode: shared memory là chuỗi text
            self.text_memory: Dict[str, List[str]] = {
                f"agent_{i}": [] for i in range(num_agents)
            }

    # ---- NORMAL (vector) mode ----
    def encode_obs(self, obs_data: Any):
        if self.text_mode:
            # Không encode thành vector, chỉ stringify
            import json
            try:
                return json.dumps(obs_data, ensure_ascii=False)
            except:
                return str(obs_data)
        vec = torch.tensor(obs_data, dtype=torch.float32).unsqueeze(0)
        return vec

    def step(self, agent_name: str, obs_vec):
        if self.text_mode:
            # Tự động tạo agent mới nếu chưa tồn tại
            if agent_name not in self.text_memory:
                self.text_memory[agent_name] = []
            
            # Thêm nội dung text vào bộ nhớ
            self.text_memory[agent_name].append(str(obs_vec))
            return self.get_shared_memory()  # trả lại tóm tắt
        else:
            # Tự động tạo memory cho agent mới
            if agent_name not in self.memories:
                self.memories[agent_name] = torch.zeros(1, getattr(self.core, "hidden_size", 512))
            
            agent_mem = self.memories[agent_name]
            shared_mem = self.get_shared_memory()
            core_out, new_mem = self.core.forward(obs_vec, agent_mem, shared_mem)
            self.memories[agent_name] = new_mem.detach()
            return core_out

    def get_shared_memory(self):
        if self.text_mode:
            # Hợp nhất tất cả các memory thành 1 đoạn text
            if not self.text_memory:
                return "No shared memory available yet."
            
            combined = []
            for k, v in self.text_memory.items():
                if v:  # Chỉ thêm nếu có dữ liệu
                    # Lấy 3 bản ghi gần nhất
                    recent = v[-3:]
                    combined.append(f"[{k}] " + " | ".join(recent))
            
            return "\n".join(combined) if combined else "No shared memory available yet."
        else:
            if not self.memories:
                return torch.zeros(1, getattr(self.core, "hidden_size", 512))
            return torch.cat(list(self.memories.values()), dim=0)