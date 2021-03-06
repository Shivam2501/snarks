package xjsnark.merkleTree;

/*Generated by MPS */

import backend.structure.CircuitGenerator;
import backend.config.Config;
import backend.auxTypes.Bit;
import backend.auxTypes.UnsignedInteger;
import backend.auxTypes.ConditionalScopeTracker;
import backend.eval.CircuitEvaluator;

public class MerkleTree extends CircuitGenerator {



  public static void main(String[] args) {
    Config.multivariateExpressionMinimization = true;
    new MerkleTree();
  }

  public MerkleTree() {
    super("MerkleTree");
    __generateCircuit();

  }



  public void __init() {
    root = new Node();
    proof = new MerklePath();
    leaf = new Node();
  }

  private Node root;
  private MerklePath proof;
  private Node leaf;

  public static final int HEIGHT = 8;
  @Override
  public void __defineInputs() {
    super.__defineInputs();





    root.__makeInput();
    leaf.__makeInput();


  }
  @Override
  public void __defineOutputs() {
    super.__defineOutputs();







  }
  @Override
  public void __defineVerifiedWitnesses() {
    super.__defineVerifiedWitnesses();






    proof.__makeVerifiedWitness();




  }
  @Override
  public void __defineWitnesses() {
    super.__defineWitnesses();









  }
  public void outsource() {
    Bit[] directionBits = proof.directionSelector.getBitElements();
    UnsignedInteger[] inputToNextHash = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{16}, 32);

    Node currentNode = leaf;
    for (int i = 0; i < HEIGHT; i++) {
      for (int j = 0; j < 16; j++) {
        {
          Bit bit_a0a0e0m = directionBits[i].copy();
          boolean c_a0a0e0m = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0e0m);
          if (c_a0a0e0m) {
            if (bit_a0a0e0m.getConstantValue()) {
              inputToNextHash[j].assign((j >= 8 ? currentNode.array[j - 8] : proof.nodes[i].array[j]), 32);
            } else {
              inputToNextHash[j].assign((j < 8 ? currentNode.array[j] : proof.nodes[i].array[j - 8]), 32);

            }
          } else {
            ConditionalScopeTracker.pushMain();
            ConditionalScopeTracker.push(bit_a0a0e0m);
            inputToNextHash[j].assign((j >= 8 ? currentNode.array[j - 8] : proof.nodes[i].array[j]), 32);

            ConditionalScopeTracker.pop();

            ConditionalScopeTracker.push(new Bit(true));

            inputToNextHash[j].assign((j < 8 ? currentNode.array[j] : proof.nodes[i].array[j - 8]), 32);
            ConditionalScopeTracker.pop();
            ConditionalScopeTracker.popMain();
          }

        }
      }
      currentNode = Util.sha2(inputToNextHash);
    }
    currentNode.assertEqual(root);
  }

  public void __generateSampleInput(CircuitEvaluator evaluator) {
    __generateRandomInput(evaluator);
  }

}
