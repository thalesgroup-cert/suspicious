import torch.nn as nn

class ResNetMLP(nn.Module):
    def __init__(self, input_dim, output_dim):
        super(ResNetMLP, self).__init__()
        self.fc1 = nn.Linear(input_dim, input_dim)
        self.fc2 = nn.Linear(input_dim, int(input_dim * 2/3))
        self.fc3 = nn.Linear(int(input_dim * 2/3), int(input_dim * 1/3))
        self.fc4 = nn.Linear(int(input_dim * 1/3), output_dim)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.5)

        self.residual_transform = nn.Linear(input_dim, int(input_dim * 1/3))

    def forward(self, x):
        # First layer
        x1 = self.relu(self.fc1(x))
        x1 = self.dropout(x1)

        # Residual Block
        x2 = self.relu(self.fc2(x1))
        x2 = self.fc3(x2)
        x2 += self.residual_transform(x1)  # Add residual connection
        x2 = self.relu(x2)

        # Output layer
        x3 = self.fc4(x2)
        return x3
